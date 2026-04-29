/* SPDX-License-Identifier: ISC */
/*
 * Send — point-in-time dataset replication producer.
 *
 *   see include/stratum/send_recv.h — surface + wire format.
 *   see docs/ARCHITECTURE.md §8.7 — protocol intent.
 *
 * Design notes:
 *
 *   - At init time, we snapshot the current set of (ds, ino, off, len,
 *     gen, paddr_0) tuples for the requested dataset, filtered by the
 *     gen range derived from from_snap_id / to_snap_id, sorted by
 *     (ino, off). Sending plays back the snapshot via repeated
 *     `stm_send_next` calls.
 *
 *   - Each EXTENT record carries the extent's PLAINTEXT bytes (decrypted
 *     from the source pool's key during `stm_send_next`). The wire is
 *     plaintext; caller wraps for transport.
 *
 *   - The running BLAKE3 csum covers EVERY record's framing+body bytes
 *     in stream order; END's body carries the final csum. Receiver
 *     replays the csum and refuses any mismatch.
 *
 *   - Decrypting an extent fails the send (STM_EBADTAG / STM_EIO bubbles
 *     up). The stream is irrecoverable from that point — caller should
 *     close + report.
 */

#include <stratum/send_recv.h>

#include <stratum/block.h>
#include <stratum/cas.h>
#include <stratum/crypto.h>
#include <stratum/extent.h>
#include <stratum/hash.h>
#include <stratum/pool.h>
#include <stratum/snapshot.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <stdlib.h>
#include <string.h>

/* Internal "frozen extent record" — what we'll replay during send.
 * R39 P2-1: carry the FULL replica set so send_next can fall back to
 * a healthy replica on per-replica AEAD failure (matching the
 * read_extent path's resilience).
 * P7-10: carry key_id so read_decrypt_extent_plaintext can resolve
 * the source DEK via stm_sync_get_dek; receiver re-encrypts under
 * its own pool's CURRENT key.
 * P7-CAS-9: carry kind + (for COLD) content_hash + cas_paddrs +
 * cas_gen captured at send_init from the source's CAS index. The
 * cas paddrs let the per-extent emit decrypt the chunk under the
 * pool metadata key + stm_ad_cas without re-acquiring sync->lock —
 * matches the HOT path's "snapshot then read directly off bdev"
 * shape. The captured cas_gen is the gen the chunk was encrypted
 * under (CAS encrypt uses sync.current_gen at intern time). */
typedef struct {
    uint64_t ino;
    uint64_t off;
    uint64_t len;
    uint64_t gen;
    uint64_t key_id;
    uint8_t  kind;             /* STM_EXTENT_KIND_HOT or STM_EXTENT_KIND_COLD */
    uint8_t  n_replicas;       /* HOT: 1..STM_EXTENT_MAX_REPLICAS; COLD: 0 */
    uint64_t paddrs[STM_EXTENT_MAX_REPLICAS];   /* HOT only */
    /* COLD-only fields. */
    uint8_t  content_hash[STM_EXTENT_HASH_LEN]; /* COLD: BLAKE3-256 */
    uint8_t  cas_n_replicas;                    /* COLD: 1..STM_CAS_MAX_REPLICAS */
    uint64_t cas_paddrs[STM_CAS_MAX_REPLICAS];  /* COLD: chunk replica paddrs */
    uint64_t cas_gen;                           /* COLD: chunk's AEAD gen */
    /* P7-16: origin (dataset_id, ino, off) for AEAD-AD reconstruction.
     * For non-reflinked extents origin matches (h->dataset_id, ino,
     * off); for reflinked extents origin is inherited from the source
     * extent at write time. The send pipeline reads bytes via
     * read_decrypt_extent_plaintext which needs origin to reconstruct
     * the AEAD AD that was used at encrypt time. */
    uint64_t origin_dataset_id;
    uint64_t origin_ino;
    uint64_t origin_off;
    /* R48 P0-1: link_gen — the gen at which this record was inserted
     * into the live index. The collect-pass send filter uses link_gen
     * (NOT gen) so reflinked records created in window (S_from, S_to]
     * are included even when their AEAD gen predates S_from. */
    uint64_t link_gen;
} send_extent_meta;

/* P7-10 / R42 P2-1: snapshot of (key_id, DEK) pairs the send needs.
 * Captured at send_init (under sync->lock) so a concurrent rotate +
 * overwrite + keyschema_sweep between init and the per-extent emit
 * can't poison the send by pruning a key still referenced by the
 * snapshotted extent set. The wipe on send_close zeros the DEKs
 * before free. */
typedef struct {
    uint64_t key_id;
    uint8_t  dek[32];
} send_dek_slot;

struct stm_send_handle {
    stm_sync          *sync;          /* borrowed; must outlive handle */
    uint64_t           dataset_id;
    uint64_t           from_snap_id;
    uint64_t           to_snap_id;
    uint64_t           to_txg;        /* upper-bound txg for the send */
    uint64_t           gen_min_excl;  /* extents with gen > this */
    uint64_t           gen_max_incl;  /* and gen ≤ this */

    send_extent_meta  *extents;       /* sorted by (ino, off) */
    size_t             n_extents;
    size_t             cap_extents;

    send_dek_slot     *deks;          /* snapshot per unique key_id */
    size_t             n_deks;
    size_t             cap_deks;

    /* Stream emission cursor:
     *   0          → emit HEADER on first stm_send_next
     *   1..n_extents → emit extents[cursor-1]
     *   n_extents+1 → emit END
     *   ≥ n_extents+2 → STM_ENOENT */
    size_t             cursor;

    /* Running BLAKE3 hasher over the wire. */
    stm_blake3_ctx    *hasher;
};

/* ------------------------------------------------------------------ */
/* Wire serialization helpers.                                         */
/* ------------------------------------------------------------------ */

static void put_le32(uint8_t *p, uint32_t v) {
    le32 le = stm_store_le32(v);
    memcpy(p, le.v, 4);
}

static void put_le64(uint8_t *p, uint64_t v) {
    le64 le = stm_store_le64(v);
    memcpy(p, le.v, 8);
}

static void write_record_hdr(uint8_t *p, uint32_t type, uint64_t body_len) {
    put_le32(p + 0, type);
    put_le32(p + 4, 0u);              /* flags reserved */
    put_le64(p + 8, body_len);
}

/* ------------------------------------------------------------------ */
/* Init: collect extents, compute gen range, set up hasher.            */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_send_handle *h;
    stm_status       err;
} send_collect_ctx;

static bool send_collect_cb(const stm_extent_record *e, void *ctx_) {
    send_collect_ctx *cc = ctx_;
    stm_send_handle *h = cc->h;

    /* R48 P0-1: filter by link_gen (the gen at which this record was
     * inserted into the live index), NOT the AEAD gen. Reflinked
     * records inherit AEAD gen from src but stamp link_gen at
     * reflink-time, so the (S_from, S_to] window catches them. For
     * non-reflinked extents link_gen == gen so the semantics match
     * pre-P7-16 (full + incremental still align with `extent.gen`-
     * sourced bracketing). */
    if (e->link_gen <= h->gen_min_excl) return true;
    if (e->link_gen > h->gen_max_incl)  return true;
    /* P7-CAS-9: extent kind validates differently for HOT vs COLD.
     * HOT: n_replicas in [1, STM_EXTENT_MAX_REPLICAS]. R39 P2-2
     * (n_replicas == 0 → STM_ECORRUPT) holds for HOT.
     * COLD: n_replicas == 0 by spec (stm_extent_record uses
     * content_hash[] instead of paddrs[]); the chunk's actual
     * replicas are captured via cas_idx lookup below. */
    if (e->kind == STM_EXTENT_KIND_HOT) {
        if (e->n_replicas < 1 || e->n_replicas > STM_EXTENT_MAX_REPLICAS) {
            cc->err = STM_ECORRUPT;
            return false;
        }
    } else if (e->kind != STM_EXTENT_KIND_COLD) {
        /* Defensive: unknown discriminator → corruption. */
        cc->err = STM_ECORRUPT;
        return false;
    }

    if (h->n_extents == h->cap_extents) {
        size_t new_cap = h->cap_extents == 0 ? 8 : h->cap_extents * 2;
        send_extent_meta *grown = realloc(h->extents,
                                             new_cap * sizeof(send_extent_meta));
        if (!grown) { cc->err = STM_ENOMEM; return false; }
        h->extents     = grown;
        h->cap_extents = new_cap;
    }
    send_extent_meta *m = &h->extents[h->n_extents++];
    memset(m, 0, sizeof *m);
    m->ino        = e->ino;
    m->off        = e->off;
    m->len        = e->len;
    m->gen        = e->gen;
    m->key_id     = e->key_id;
    m->kind       = (uint8_t)e->kind;
    if (e->kind == STM_EXTENT_KIND_HOT) {
        m->n_replicas = e->n_replicas;
        for (uint8_t i = 0; i < e->n_replicas; i++) m->paddrs[i] = e->paddrs[i];
    } else {
        /* COLD: capture content_hash; cas_idx lookup happens after
         * the iter completes (cas_lookup takes cas_idx.lock; the iter
         * cb is allowed to call into it but the cleaner pattern is to
         * batch lookups outside the iter). */
        memcpy(m->content_hash, e->content_hash, STM_EXTENT_HASH_LEN);
    }
    /* P7-16: capture origin so the per-extent send can reconstruct AD. */
    m->origin_dataset_id = e->origin_dataset_id;
    m->origin_ino        = e->origin_ino;
    m->origin_off        = e->origin_off;
    /* R48 P0-1: capture link_gen for the collect-pass filter. */
    m->link_gen          = e->link_gen;
    return true;
}

stm_status stm_send_init(stm_sync *sync,
                            uint64_t dataset_id,
                            uint64_t from_snap_id,
                            uint64_t to_snap_id,
                            stm_send_handle **out_handle)
{
    if (!sync || !out_handle) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    *out_handle = NULL;

    /* Resolve gen range from snapshot ids. */
    uint64_t gen_min_excl = 0;
    uint64_t gen_max_incl = 0;

    stm_snapshot_index *snap_idx = stm_sync_snapshot_index(sync);
    if (!snap_idx) return STM_EINVAL;

    /* P7-8: filter by `extent_txg`, the sync.current_gen captured at
     * snap-create. This is the SAME counter space as `extent.gen`, so
     * the filter `gen_min_excl < extent.gen <= gen_max_incl` is now
     * authoritative (was best-effort pre-P7-8 when we used
     * `created_txg`, the snap-index counter). */
    if (from_snap_id != 0) {
        stm_snapshot_entry from_entry;
        stm_status ls = stm_snapshot_lookup(snap_idx, from_snap_id, &from_entry);
        if (ls != STM_OK) return STM_ENOENT;
        if (from_entry.dataset_id != dataset_id) return STM_EINVAL;
        gen_min_excl = from_entry.extent_txg;
    }
    if (to_snap_id != 0) {
        stm_snapshot_entry to_entry;
        stm_status ls = stm_snapshot_lookup(snap_idx, to_snap_id, &to_entry);
        if (ls != STM_OK) return STM_ENOENT;
        if (to_entry.dataset_id != dataset_id) return STM_EINVAL;
        gen_max_incl = to_entry.extent_txg;
    } else {
        /* Full or open-ended: cap at the index's current_txg. */
        stm_extent_index *eidx = stm_sync_extent_index(sync);
        if (!eidx) return STM_EINVAL;
        stm_status ts = stm_extent_index_current_txg(eidx, &gen_max_incl);
        if (ts != STM_OK) return ts;
    }
    /* From > To is nonsense — incremental send across snaps must have
     * the older snap (from) captured at a strictly LOWER extent_txg
     * than the newer (to). Equal extent_txg means no Write happened
     * between the two — empty diff, but still rejected here as a
     * caller bug rather than silently producing zero EXTENT records. */
    if (from_snap_id != 0 && to_snap_id != 0 && gen_min_excl >= gen_max_incl)
        return STM_EINVAL;

    stm_send_handle *h = calloc(1, sizeof(*h));
    if (!h) return STM_ENOMEM;
    h->sync         = sync;
    h->dataset_id   = dataset_id;
    h->from_snap_id = from_snap_id;
    h->to_snap_id   = to_snap_id;
    h->to_txg       = gen_max_incl;
    h->gen_min_excl = gen_min_excl;
    h->gen_max_incl = gen_max_incl;

    h->hasher = stm_blake3_new();
    if (!h->hasher) { free(h); return STM_ENOMEM; }

    /* Snapshot the matching extent set. */
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    if (!eidx) {
        stm_blake3_free(h->hasher);
        free(h);
        return STM_EINVAL;
    }
    send_collect_ctx cc = { .h = h, .err = STM_OK };
    stm_status is = stm_extent_iter_ds(eidx, dataset_id, send_collect_cb, &cc);
    if (is != STM_OK || cc.err != STM_OK) {
        free(h->extents);
        stm_blake3_free(h->hasher);
        free(h);
        return is != STM_OK ? is : cc.err;
    }

    /* P7-CAS-9: resolve CAS chunk paddrs + gen for every captured
     * COLD extent. cas_lookup takes cas_idx.lock; do this AFTER
     * extent_iter_ds returns so we don't nest cas_idx.lock under
     * extent_idx.lock (cleanest order: each per-extent lookup
     * acquires + releases cas_idx.lock). A concurrent
     * stm_sync_commit could run auto_gc_sweep between iter and
     * lookup — the sweep only reclaims refcount=0 entries, and
     * every captured COLD extent's chunk has refcount >= 1 (the
     * extent record itself holds the ref), so the chunk stays
     * alive. */
    {
        stm_cas_index *cidx = stm_sync_cas_index(sync);
        for (size_t i = 0; i < h->n_extents; i++) {
            send_extent_meta *m = &h->extents[i];
            if (m->kind != STM_EXTENT_KIND_COLD) continue;
            if (!cidx) {
                free(h->extents);
                stm_blake3_free(h->hasher);
                free(h);
                return STM_ECORRUPT;
            }
            stm_cas_record cas_rec;
            stm_status ls = stm_cas_lookup(cidx, m->content_hash, &cas_rec);
            if (ls != STM_OK) {
                /* STM_ENOENT here is a dangling-hash bug —
                 * CAS index inconsistent with extent index. */
                free(h->extents);
                stm_blake3_free(h->hasher);
                free(h);
                return (ls == STM_ENOENT) ? STM_ECORRUPT : ls;
            }
            if (cas_rec.length != m->len) {
                free(h->extents);
                stm_blake3_free(h->hasher);
                free(h);
                return STM_ECORRUPT;
            }
            if (cas_rec.n_replicas < 1
                || cas_rec.n_replicas > STM_CAS_MAX_REPLICAS) {
                free(h->extents);
                stm_blake3_free(h->hasher);
                free(h);
                return STM_ECORRUPT;
            }
            m->cas_n_replicas = cas_rec.n_replicas;
            for (uint8_t k = 0; k < cas_rec.n_replicas; k++) {
                m->cas_paddrs[k] = cas_rec.paddrs[k];
            }
            m->cas_gen = cas_rec.gen;
        }
    }

    /* P7-10 / R42 P2-1: snapshot DEKs for every unique key_id the
     * collected extents reference. Without this, a concurrent
     * `stm_sync_rotate_dataset_key` + `stm_sync_write_extent`
     * (overwrites in the live extent index, dropping the snapshotted
     * paddrs into a snap dead-list) + `stm_sync_keyschema_sweep`
     * (sees zero LIVE refs and prunes the now-RETIRED key) would
     * leave the send unable to decrypt bytes that ARE still on disk.
     * The snapshot pins the DEK in the handle's RAM regardless of
     * subsequent keyschema mutations.
     *
     * Capture is bounded: at most `n_extents` unique key_ids; in
     * practice |unique key_ids| ≤ rotation count for the dataset
     * over the snap range, typically tiny. */
    for (size_t i = 0; i < h->n_extents; i++) {
        /* P7-CAS-9: COLD extents decrypt under the pool metadata
         * key (not a per-dataset DEK; ARCH §7.6.3), so skip the DEK
         * snapshot for them. The per-extent emit reads cold chunks
         * directly via cas_paddrs + stm_ad_cas + metadata_key. */
        if (h->extents[i].kind == STM_EXTENT_KIND_COLD) continue;

        uint64_t kid = h->extents[i].key_id;
        bool already = false;
        for (size_t j = 0; j < h->n_deks; j++) {
            if (h->deks[j].key_id == kid) { already = true; break; }
        }
        if (already) continue;

        if (h->n_deks == h->cap_deks) {
            size_t new_cap = h->cap_deks == 0 ? 4 : h->cap_deks * 2;
            send_dek_slot *grown = malloc(new_cap * sizeof *grown);
            if (!grown) {
                if (h->deks) {
                    stm_ct_memzero(h->deks, h->cap_deks * sizeof *h->deks);
                    free(h->deks);
                }
                free(h->extents);
                stm_blake3_free(h->hasher);
                free(h);
                return STM_ENOMEM;
            }
            if (h->deks && h->n_deks > 0)
                memcpy(grown, h->deks, h->n_deks * sizeof *h->deks);
            memset(grown + h->n_deks, 0,
                     (new_cap - h->n_deks) * sizeof *grown);
            if (h->deks) {
                stm_ct_memzero(h->deks, h->cap_deks * sizeof *h->deks);
                free(h->deks);
            }
            h->deks = grown;
            h->cap_deks = new_cap;
        }

        send_dek_slot *slot = &h->deks[h->n_deks++];
        slot->key_id = kid;
        stm_status ks = stm_sync_get_dek(sync, dataset_id, kid, slot->dek);
        if (ks != STM_OK) {
            /* No DEK for an extent the iter just collected — must
             * be a sweep race that resolved against this exact
             * key_id between iter and lookup. Bail; caller can
             * retry. Wipe whatever DEKs we did capture. */
            stm_ct_memzero(h->deks, h->cap_deks * sizeof *h->deks);
            free(h->deks);
            free(h->extents);
            stm_blake3_free(h->hasher);
            free(h);
            return (ks == STM_ENOENT) ? STM_EBUSY : ks;
        }
    }

    *out_handle = h;
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* HEADER record emission.                                             */
/* ------------------------------------------------------------------ */

static stm_status emit_header_locked(stm_send_handle *h,
                                        uint8_t *out, size_t out_cap)
{
    /* Total: 16 (framing) + 52 (body) = 68 bytes. Layout per
     * send_recv.h: magic + version + pool_uuid + dataset_id +
     * from_snap_id + to_snap_id + reserved. */
    const size_t need = STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN;
    if (out_cap < need) return STM_ERANGE;

    write_record_hdr(out, STM_SEND_REC_HEADER, STM_SEND_HEADER_BODY_LEN);

    uint8_t *body = out + STM_SEND_RECORD_HDR_LEN;
    memset(body, 0, STM_SEND_HEADER_BODY_LEN);

    const uint64_t *puuid = stm_pool_uuid(stm_sync_pool(h->sync));
    put_le32(body + 0,  STM_SEND_MAGIC);
    put_le32(body + 4,  STM_SEND_VERSION);
    put_le64(body + 8,  puuid[0]);
    put_le64(body + 16, puuid[1]);
    put_le64(body + 24, h->dataset_id);
    put_le64(body + 32, h->from_snap_id);
    put_le64(body + 40, h->to_snap_id);
    /* body offset 48..52 reserved zero. */

    stm_blake3_update(h->hasher, out, need);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* EXTENT record emission.                                             */
/* ------------------------------------------------------------------ */

static stm_status read_decrypt_extent_plaintext(stm_send_handle *h,
                                                   const send_extent_meta *m,
                                                   uint8_t *out_plain)
{
    /* AEGIS-256 hardcoded — matches stm_sync_write_extent. */
    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_EINVAL;

    size_t total = m->len + tag_len;
    void *cbuf = malloc(total);
    if (!cbuf) return STM_ENOMEM;

    /* AEAD AD — same shape as stm_sync_write_extent. P7-16: AD binds
     * to `origin`, not to the live (h->dataset_id, m->ino, m->off).
     * For non-reflinked extents origin matches the live identity; for
     * reflinked extents origin is inherited from the source — the
     * AEAD ciphertext at m->paddrs[*] was bound to origin at write
     * time so AD reconstructs the same identity. */
    stm_ad_extent ad;
    memset(&ad, 0, sizeof ad);
    ad.magic        = STM_AD_MAGIC_EXTENT;
    ad.version      = STM_AD_VERSION_EXTENT;
    const uint64_t *puuid = stm_pool_uuid(stm_sync_pool(h->sync));
    ad.pool_uuid[0] = puuid[0];
    ad.pool_uuid[1] = puuid[1];
    ad.dataset_id   = m->origin_dataset_id;
    ad.ino          = m->origin_ino;
    ad.offset       = m->origin_off;
    ad.content_kind = 0;

    /* P7-10 / R42 P2-1: resolve the source DEK from the handle's
     * init-time snapshot. The snapshot is pinned for the handle's
     * lifetime regardless of subsequent rotate/sweep — a concurrent
     * sweep can prune the keyschema entry, but the bytes at
     * m->paddrs[0] (which may be in a snap dead-list rather than
     * the live extent index) remain decryptable under the captured
     * DEK. STM_ENOENT here is impossible by construction (every
     * collected extent's key_id was DEK-captured at init); treat
     * as a programming-error STM_ECORRUPT to fail loudly if the
     * invariant ever drifts. */
    const uint8_t *dek_p = NULL;
    for (size_t i = 0; i < h->n_deks; i++) {
        if (h->deks[i].key_id == m->key_id) {
            dek_p = h->deks[i].dek;
            break;
        }
    }
    if (!dek_p) { free(cbuf); return STM_ECORRUPT; }

    /* R39 P2-1: walk every replica until one AEAD-decrypts cleanly,
     * mirroring sync.c's stm_sync_read_extent. AEAD nonce is canonical
     * `(paddrs[0], gen)` regardless of which replica's bytes we
     * sourced, because all replicas were encrypted under that nonce
     * and replicated bytewise per P7-6. A failed primary doesn't
     * abort the send if any sibling replica is healthy. */
    stm_status last_err = STM_EBADTAG;
    for (uint8_t i = 0; i < m->n_replicas; i++) {
        uint16_t dev = stm_paddr_device(m->paddrs[i]);
        stm_bdev *bd = stm_pool_device_bdev(stm_sync_pool(h->sync), dev);
        if (!bd) { last_err = STM_EINVAL; continue; }
        uint64_t boff = stm_paddr_offset(m->paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_status rs = stm_bdev_read(bd, boff, cbuf, total);
        if (rs != STM_OK) { last_err = rs; continue; }

        size_t pt_out = 0;
        stm_status ds = stm_extent_decrypt(mode, dek_p,
                                              m->paddrs[0], m->gen,
                                              &ad, cbuf, total,
                                              out_plain, m->len, &pt_out);
        if (ds == STM_OK) {
            free(cbuf);
            return STM_OK;
        }
        last_err = ds;
    }

    free(cbuf);
    return last_err;
}

/* P7-CAS-9: decrypt a COLD extent's chunk plaintext from the source
 * pool's CAS replicas. Mirrors sync.c's `stm_sync_read_extent_locked`
 * COLD branch (line ~4504) but uses paddrs snapshotted at send_init
 * (instead of an under-lock cas_idx lookup) so the send doesn't
 * nest sync->lock for every emit. AEAD nonce: (paddrs[0], cas_gen,
 * pool_uuid). AEAD AD: stm_ad_cas(pool_uuid, content_hash). Key:
 * pool metadata key (cross-dataset shareable per ARCH §7.6.3). */
static stm_status read_decrypt_cold_chunk_plaintext(stm_send_handle *h,
                                                       const send_extent_meta *m,
                                                       uint8_t *out_plain)
{
    if (m->cas_n_replicas == 0
        || m->cas_n_replicas > STM_CAS_MAX_REPLICAS) return STM_ECORRUPT;

    stm_aead_mode mode = STM_AEAD_AEGIS256;
    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_EINVAL;

    size_t total = m->len + tag_len;
    void *cbuf = malloc(total);
    if (!cbuf) return STM_ENOMEM;

    /* Pack stm_ad_cas (56 bytes; magic + version + pool_uuid +
     * content_hash). */
    stm_ad_cas cad;
    memset(&cad, 0, sizeof cad);
    cad.magic        = STM_AD_MAGIC_CAS;
    cad.version      = STM_AD_VERSION_CAS;
    const uint64_t *puuid = stm_pool_uuid(stm_sync_pool(h->sync));
    cad.pool_uuid[0] = puuid[0];
    cad.pool_uuid[1] = puuid[1];
    memcpy(cad.content_hash, m->content_hash, STM_CAS_HASH_LEN);
    uint8_t cad_packed[STM_AD_CAS_PACKED_LEN];
    stm_ad_cas_pack(&cad, cad_packed);

    /* Nonce: paddrs[0] || cas_gen || pool_uuid (LE). */
    uint8_t nonce[STM_AEAD_NONCE_LEN];
    {
        le64 p_le  = stm_store_le64(m->cas_paddrs[0]);
        le64 g_le  = stm_store_le64(m->cas_gen);
        le64 u0_le = stm_store_le64(puuid[0]);
        le64 u1_le = stm_store_le64(puuid[1]);
        memcpy(nonce +  0, p_le.v,  8);
        memcpy(nonce +  8, g_le.v,  8);
        memcpy(nonce + 16, u0_le.v, 8);
        memcpy(nonce + 24, u1_le.v, 8);
    }

    const uint8_t *mkey = stm_sync_metadata_key(h->sync);
    if (!mkey) { free(cbuf); return STM_ECORRUPT; }

    stm_status last_err = STM_EBADTAG;
    for (uint8_t i = 0; i < m->cas_n_replicas; i++) {
        uint16_t dev = stm_paddr_device(m->cas_paddrs[i]);
        stm_bdev *bd = stm_pool_device_bdev(stm_sync_pool(h->sync), dev);
        if (!bd) { last_err = STM_EINVAL; continue; }
        uint64_t boff = stm_paddr_offset(m->cas_paddrs[i]) * (uint64_t)STM_UB_SIZE;
        stm_status rs = stm_bdev_read(bd, boff, cbuf, total);
        if (rs != STM_OK) { last_err = rs; continue; }

        size_t pt_out = 0;
        stm_status ds = stm_aead_decrypt(mode, mkey, nonce,
                                            cad_packed, STM_AD_CAS_PACKED_LEN,
                                            cbuf, total,
                                            out_plain, &pt_out);
        if (ds == STM_OK) {
            if (pt_out != m->len) { last_err = STM_ECORRUPT; continue; }
            free(cbuf);
            return STM_OK;
        }
        last_err = ds;
    }

    free(cbuf);
    return last_err;
}

static stm_status emit_extent_locked(stm_send_handle *h,
                                        const send_extent_meta *m,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    /* P7-CAS-9: HOT extents use the legacy 32-byte body meta;
     * COLD extents prefix the plaintext with a 32-byte content_hash
     * (total 64 bytes meta) and set STM_SEND_FLAG_COLD in the
     * framing header's flags field. */
    bool is_cold = (m->kind == STM_EXTENT_KIND_COLD);
    size_t meta_len = is_cold ? STM_SEND_COLD_EXTENT_META_LEN
                              : STM_SEND_EXTENT_META_LEN;
    size_t need = STM_SEND_RECORD_HDR_LEN + meta_len + m->len;
    if (out_cap < need) return STM_ERANGE;

    uint64_t body_len = (uint64_t)meta_len + m->len;
    /* Custom record header: type=EXTENT, flags=COLD if applicable. */
    put_le32(out + 0, STM_SEND_REC_EXTENT);
    put_le32(out + 4, is_cold ? STM_SEND_FLAG_COLD : 0u);
    put_le64(out + 8, body_len);

    uint8_t *body = out + STM_SEND_RECORD_HDR_LEN;
    put_le64(body + 0,  m->ino);
    put_le64(body + 8,  m->off);
    put_le64(body + 16, m->len);
    put_le64(body + 24, m->gen);

    if (is_cold) {
        memcpy(body + STM_SEND_EXTENT_META_LEN, m->content_hash,
                  STM_EXTENT_HASH_LEN);
        stm_status ds = read_decrypt_cold_chunk_plaintext(
                h, m, body + STM_SEND_COLD_EXTENT_META_LEN);
        if (ds != STM_OK) return ds;
    } else {
        /* HOT path: decrypt the extent's plaintext directly into
         * the output buffer (extent ciphertext on bdev → plaintext). */
        stm_status ds = read_decrypt_extent_plaintext(
                h, m, body + STM_SEND_EXTENT_META_LEN);
        if (ds != STM_OK) return ds;
    }

    stm_blake3_update(h->hasher, out, need);
    *out_len = need;
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* END record emission.                                                */
/* ------------------------------------------------------------------ */

static stm_status emit_end_locked(stm_send_handle *h,
                                     uint8_t *out, size_t out_cap)
{
    const size_t need = STM_SEND_RECORD_HDR_LEN + STM_SEND_END_BODY_LEN;
    if (out_cap < need) return STM_ERANGE;

    write_record_hdr(out, STM_SEND_REC_END, STM_SEND_END_BODY_LEN);

    /* Compute final csum BEFORE writing it (it covers all prior
     * records, NOT the END body itself). */
    uint8_t *body = out + STM_SEND_RECORD_HDR_LEN;
    stm_blake3_final(h->hasher, body, STM_SEND_END_BODY_LEN);

    /* The END's framing IS in the csum's input domain conceptually,
     * but here we deliberately exclude END's body from the csum's
     * inputs — receiver's csum check is "compare END.body to recv-
     * computed BLAKE3(prior records)". */
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Public dispatch.                                                    */
/* ------------------------------------------------------------------ */

stm_status stm_send_next(stm_send_handle *h,
                            void *out_buf, size_t out_cap,
                            size_t *out_len,
                            size_t *out_len_needed)
{
    if (!h || !out_buf || !out_len || !out_len_needed) return STM_EINVAL;
    *out_len = 0;
    *out_len_needed = 0;

    /* Stream cursor:
     *   cursor == 0           → HEADER
     *   1..n_extents          → extents[cursor-1]
     *   n_extents+1           → END
     *   ≥ n_extents+2         → STM_ENOENT */
    if (h->cursor > h->n_extents + 1u) return STM_ENOENT;

    uint8_t *p = out_buf;
    if (h->cursor == 0) {
        size_t need = STM_SEND_RECORD_HDR_LEN + STM_SEND_HEADER_BODY_LEN;
        if (out_cap < need) { *out_len_needed = need; return STM_ERANGE; }
        stm_status hs = emit_header_locked(h, p, out_cap);
        if (hs != STM_OK) return hs;
        *out_len = need;
        h->cursor = 1;
        return STM_OK;
    }

    if (h->cursor <= h->n_extents) {
        const send_extent_meta *m = &h->extents[h->cursor - 1];
        size_t meta_len = (m->kind == STM_EXTENT_KIND_COLD)
                              ? STM_SEND_COLD_EXTENT_META_LEN
                              : STM_SEND_EXTENT_META_LEN;
        size_t need = STM_SEND_RECORD_HDR_LEN + meta_len + m->len;
        if (out_cap < need) { *out_len_needed = need; return STM_ERANGE; }
        size_t emitted = 0;
        stm_status es = emit_extent_locked(h, m, p, out_cap, &emitted);
        if (es != STM_OK) return es;
        *out_len = emitted;
        h->cursor++;
        return STM_OK;
    }

    /* cursor == n_extents + 1: emit END. */
    size_t need = STM_SEND_RECORD_HDR_LEN + STM_SEND_END_BODY_LEN;
    if (out_cap < need) { *out_len_needed = need; return STM_ERANGE; }
    stm_status es = emit_end_locked(h, p, out_cap);
    if (es != STM_OK) return es;
    *out_len = need;
    h->cursor++;
    return STM_OK;
}

void stm_send_close(stm_send_handle *h)
{
    if (!h) return;
    free(h->extents);
    if (h->deks) {
        stm_ct_memzero(h->deks, h->cap_deks * sizeof *h->deks);
        free(h->deks);
    }
    if (h->hasher) stm_blake3_free(h->hasher);
    free(h);
}
