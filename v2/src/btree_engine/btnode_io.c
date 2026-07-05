/* SPDX-License-Identifier: ISC */
/*
 * btree_engine — per-node device I/O.
 *
 * The store layer: encode a node, reserve a fresh paddr, AEAD-encrypt
 * under (paddr, gen), Merkle-csum the ciphertext, write; and the
 * reverse — read, Merkle-check, decrypt, decode into a fresh eng_node.
 * Lifts the proven patterns from btree_store/serialize.c — child-bptr
 * pack/unpack, the ciphertext BLAKE3 Merkle link, the post-decrypt
 * plaintext self-csum restore — and runs them at the engine's 16-KiB
 * node size instead of the legacy 128-KiB STM_BTNODE_SIZE.
 *
 * Engine extension over serialize.c's child bptr: the child's birth
 * gen is stored in the bptr's bp_reserved2[0..8). Under incremental
 * COW every node has its own gen (design §3.9), and the gen is an
 * AEAD-nonce input needed to decrypt the child — so, like bp_csum, it
 * must be carried by the parent.
 */

#include "engine_internal.h"

#include <stratum/hash.h>
#include <stratum/super.h>

#include <stdlib.h>
#include <string.h>

/* Ciphertext region of an engine node — everything but the trailing
 * 32-byte AEAD-tag / Merkle-csum slot. */
#define ENG_CT_LEN   (STM_BTREE_ENGINE_NODE_SIZE - STM_BTNODE_CSUM_SIZE)

/* ========================================================================= */
/* Merkle + child-bptr helpers.                                                */
/* ========================================================================= */

/* BLAKE3 over the ciphertext region — the Merkle link a parent records
 * for a child (and the uberblock records for the root). */
static void compute_ct_csum(const uint8_t *buf,
                             uint8_t out[STM_BTNODE_CSUM_SIZE])
{
    stm_blake3_hash h;
    stm_blake3(buf, ENG_CT_LEN, &h);
    memcpy(out, h.bytes, STM_BTNODE_CSUM_SIZE);
}

static stm_status check_merkle_link(const uint8_t *buf,
                                     const uint8_t expected[STM_BTNODE_CSUM_SIZE])
{
    uint8_t actual[STM_BTNODE_CSUM_SIZE];
    compute_ct_csum(buf, actual);
    if (memcmp(actual, expected, STM_BTNODE_CSUM_SIZE) != 0)
        return STM_ECORRUPT;
    return STM_OK;
}

/* After AEAD-decrypt the trailing 32 bytes hold the AEAD tag, not the
 * plaintext self-csum the btnode codec's decode path expects. Recompute
 * BLAKE3 over [0, ENG_CT_LEN) and write it back so the codec's
 * self-csum check passes — the same fix-up serialize.c performs. */
static void restore_plaintext_self_csum(uint8_t *buf)
{
    stm_blake3_hash h;
    stm_blake3(buf, ENG_CT_LEN, &h);
    memcpy(buf + ENG_CT_LEN, h.bytes, STM_BTNODE_CSUM_SIZE);
}

/* Pack a 64-byte child bptr: paddr + kind + Merkle csum + birth gen. */
static void encode_child_bptr(uint64_t paddr, uint8_t kind, uint64_t gen,
                               const uint8_t csum[STM_BTNODE_CSUM_SIZE],
                               uint8_t out[STM_BTNODE_CHILD_BPTR_SIZE])
{
    stm_bptr bp;
    memset(&bp, 0, sizeof bp);
    bp.bp_paddr = stm_store_le64(paddr);
    bp.bp_kind  = kind;
    memcpy(bp.bp_csum, csum, STM_BTNODE_CSUM_SIZE);
    le64 g = stm_store_le64(gen);            /* engine: gen in reserved2 */
    memcpy(bp.bp_reserved2, g.v, 8);
    memcpy(out, &bp, sizeof bp);
}

static void decode_child_bptr(const uint8_t in[STM_BTNODE_CHILD_BPTR_SIZE],
                               uint64_t *out_paddr, uint8_t *out_kind,
                               uint8_t out_csum[STM_BTNODE_CSUM_SIZE],
                               uint64_t *out_gen)
{
    stm_bptr bp;
    memcpy(&bp, in, sizeof bp);
    *out_paddr = stm_load_le64(bp.bp_paddr);
    *out_kind  = bp.bp_kind;
    memcpy(out_csum, bp.bp_csum, STM_BTNODE_CSUM_SIZE);
    le64 g;
    memcpy(g.v, bp.bp_reserved2, 8);
    *out_gen = stm_load_le64(g);
}

/* ========================================================================= */
/* Spill blocks — out-of-line storage for large leaf values (9.6-impl-3).      */
/* see v2/docs/phase-9.6-impl-3-spill-design.md §4.                            */
/* ========================================================================= */

/* Lay out, AEAD-encrypt, and write one spill block at the already-
 * reserved paddr `p`; `out_csum` gets the block's ciphertext BLAKE3
 * (the Merkle link the parent / previous block records). Does NOT free
 * `p` on failure — the chain writer logs every reserved paddr into
 * pending.fresh before calling this, so the failed-flush handler is the
 * sole owner of that reclaim (no double-free). */
static stm_status eng_spill_block_emit(stm_btree_engine *eng,
                                        uint64_t p, uint64_t gen,
                                        const uint8_t *chunk, uint32_t chunk_len,
                                        bool have_next, uint64_t next_paddr,
                                        uint64_t next_gen,
                                        const uint8_t next_csum[STM_BTNODE_CSUM_SIZE],
                                        uint8_t out_csum[STM_BTNODE_CSUM_SIZE])
{
    uint8_t *b = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    if (!b) return STM_ENOMEM;

    le64 m  = stm_store_le64(ENG_SPILL_MAGIC);
    le32 cl = stm_store_le32(chunk_len);
    le32 fl = stm_store_le32(have_next ? ENG_SPILL_FLAG_HAS_NEXT : 0u);
    memcpy(b + 0,  m.v,  8);
    memcpy(b + 8,  cl.v, 4);
    memcpy(b + 12, fl.v, 4);
    if (have_next)
        encode_child_bptr(next_paddr, ENG_SPILL_BPTR_KIND, next_gen,
                          next_csum, b + 16);
    if (chunk_len) memcpy(b + ENG_SPILL_HDR_SIZE, chunk, chunk_len);

    stm_status s = stm_btree_node_encrypt(&eng->cx, p, gen, b,
                                          STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) { free(b); return s; }
    compute_ct_csum(b, out_csum);
    s = eng->vt->write(eng->vt_ctx, p, b, STM_BTREE_ENGINE_NODE_SIZE);
    free(b);
    return s;
}

stm_status eng_spill_chain_write(stm_btree_engine *eng,
                                  const uint8_t *val, uint32_t val_len,
                                  uint64_t gen, eng_spill *sp,
                                  paddr_vec *fresh)
{
    uint32_t n = (uint32_t)(((uint64_t)val_len + ENG_SPILL_CHUNK_CAP - 1u) /
                            ENG_SPILL_CHUNK_CAP);
    if (n == 0u || n > ENG_SPILL_MAX_BLOCKS) return STM_ERANGE;

    uint64_t *blocks = malloc((size_t)n * sizeof *blocks);
    if (!blocks) return STM_ENOMEM;

    /* Reserve fresh-vec room for all n paddrs up front, so each
     * per-block push — after the paddr is reserved, before the block is
     * written — is infallible and a mid-chain failure still leaves
     * every reserved paddr logged for the failed-flush handler. */
    stm_status s = paddr_vec_reserve(fresh, n);
    if (s != STM_OK) { free(blocks); return s; }

    bool     have_next  = false;
    uint64_t next_paddr = 0, next_gen = 0;
    uint8_t  next_csum[STM_BTNODE_CSUM_SIZE];
    uint8_t  head_csum[STM_BTNODE_CSUM_SIZE];
    memset(next_csum, 0, sizeof next_csum);
    memset(head_csum, 0, sizeof head_csum);

    /* Tail-to-head: a block's `next` bptr is its already-written
     * successor's, so every `next` carries a real csum. */
    for (uint32_t k = 0; k < n; k++) {
        uint32_t i = n - 1u - k;
        uint64_t p = 0;
        s = eng->vt->reserve(eng->vt_ctx, &p);
        if (s != STM_OK) { free(blocks); return s; }
        (void)paddr_vec_push(fresh, p);             /* reserved above */
        blocks[i] = p;

        uint64_t off       = (uint64_t)i * ENG_SPILL_CHUNK_CAP;
        uint64_t remaining = (uint64_t)val_len - off;
        uint32_t chunk_len = (uint32_t)(remaining < ENG_SPILL_CHUNK_CAP
                                        ? remaining : ENG_SPILL_CHUNK_CAP);
        uint8_t  csum_i[STM_BTNODE_CSUM_SIZE];
        s = eng_spill_block_emit(eng, p, gen, val + off, chunk_len,
                                 have_next, next_paddr, next_gen, next_csum,
                                 csum_i);
        if (s != STM_OK) { free(blocks); return s; }  /* p already in fresh */

        next_paddr = p;
        next_gen   = gen;
        memcpy(next_csum, csum_i, STM_BTNODE_CSUM_SIZE);
        have_next  = true;
        if (i == 0u) memcpy(head_csum, csum_i, STM_BTNODE_CSUM_SIZE);
    }

    sp->blocks   = blocks;
    sp->n_blocks = n;
    sp->head_gen = gen;
    memcpy(sp->head_csum, head_csum, STM_BTNODE_CSUM_SIZE);
    sp->dirty    = false;
    return STM_OK;
}

/* Read + Merkle/AEAD-check one spill block at (paddr, gen) into the
 * caller's NODE_SIZE scratch buffer, parse the header. */
static stm_status eng_spill_block_read(stm_btree_engine *eng,
                                        uint64_t paddr, uint64_t gen,
                                        const uint8_t expect[STM_BTNODE_CSUM_SIZE],
                                        uint8_t *scratch,
                                        uint32_t *out_chunk_len,
                                        bool *out_has_next,
                                        uint64_t *out_next_paddr,
                                        uint64_t *out_next_gen,
                                        uint8_t out_next_csum[STM_BTNODE_CSUM_SIZE])
{
    stm_status s = eng->vt->read(eng->vt_ctx, paddr, scratch,
                                 STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) return s;
    s = check_merkle_link(scratch, expect);
    if (s != STM_OK) return s;
    s = stm_btree_node_decrypt(&eng->cx, paddr, gen, scratch,
                               STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) return s;

    le64 m;  memcpy(m.v,  scratch + 0,  8);
    le32 cl; memcpy(cl.v, scratch + 8,  4);
    le32 fl; memcpy(fl.v, scratch + 12, 4);
    if (stm_load_le64(m) != ENG_SPILL_MAGIC)        return STM_ECORRUPT;
    uint32_t chunk_len = stm_load_le32(cl);
    uint32_t flags     = stm_load_le32(fl);
    if (chunk_len > ENG_SPILL_CHUNK_CAP)            return STM_ECORRUPT;
    if (flags & ~(uint32_t)ENG_SPILL_FLAG_HAS_NEXT) return STM_ECORRUPT;

    *out_chunk_len = chunk_len;
    *out_has_next  = (flags & ENG_SPILL_FLAG_HAS_NEXT) != 0u;
    if (*out_has_next) {
        uint8_t kind = 0;
        decode_child_bptr(scratch + 16, out_next_paddr, &kind,
                          out_next_csum, out_next_gen);
    } else {
        *out_next_paddr = 0;
        *out_next_gen   = 0;
        memset(out_next_csum, 0, STM_BTNODE_CSUM_SIZE);
    }
    return STM_OK;
}

/* Walk the chain rooted at (head_paddr, head_gen, head_csum) for
 * exactly `total_len` value bytes, Merkle/AEAD-checking each block. If
 * `out_val` is non-NULL the value is materialised into a fresh buffer
 * and the block paddrs into *out_blocks; if NULL the walk only
 * verifies. The expected block count is derived from `total_len`, so a
 * chain longer or shorter than that is rejected as corrupt. */
static stm_status spill_chain_walk(stm_btree_engine *eng,
                                    uint64_t head_paddr, uint64_t head_gen,
                                    const uint8_t head_csum[STM_BTNODE_CSUM_SIZE],
                                    uint64_t total_len,
                                    uint8_t **out_val, uint64_t **out_blocks,
                                    uint32_t *out_n_blocks)
{
    if (total_len == 0u || total_len > STM_BTREE_ENGINE_MAX_VALUE_BYTES)
        return STM_ECORRUPT;
    uint32_t n = (uint32_t)((total_len + ENG_SPILL_CHUNK_CAP - 1u) /
                            ENG_SPILL_CHUNK_CAP);

    uint8_t  *scratch = malloc(STM_BTREE_ENGINE_NODE_SIZE);
    uint8_t  *val     = out_val ? malloc((size_t)total_len) : NULL;
    uint64_t *blocks  = out_val ? malloc((size_t)n * sizeof *blocks) : NULL;
    if (!scratch || (out_val && (!val || !blocks))) {
        free(scratch); free(val); free(blocks);
        return STM_ENOMEM;
    }

    uint64_t paddr = head_paddr, gen = head_gen;
    uint8_t  csum[STM_BTNODE_CSUM_SIZE];
    memcpy(csum, head_csum, STM_BTNODE_CSUM_SIZE);
    uint64_t off = 0;
    stm_status s = STM_OK;

    for (uint32_t i = 0; i < n; i++) {
        uint32_t cl = 0;
        bool     hn = false;
        uint64_t np = 0, ng = 0;
        uint8_t  nc[STM_BTNODE_CSUM_SIZE];
        s = eng_spill_block_read(eng, paddr, gen, csum, scratch,
                                 &cl, &hn, &np, &ng, nc);
        if (s != STM_OK) break;
        if ((uint64_t)cl > total_len - off) { s = STM_ECORRUPT; break; }
        bool last = (i == n - 1u);
        if (last == hn) { s = STM_ECORRUPT; break; }   /* chain-shape */
        if (val)    memcpy(val + off, scratch + ENG_SPILL_HDR_SIZE, cl);
        if (blocks) blocks[i] = paddr;
        off  += cl;
        paddr = np;
        gen   = ng;
        memcpy(csum, nc, STM_BTNODE_CSUM_SIZE);
    }
    if (s == STM_OK && off != total_len) s = STM_ECORRUPT;

    free(scratch);
    if (s != STM_OK) { free(val); free(blocks); return s; }
    if (out_val)      *out_val      = val;
    if (out_blocks)   *out_blocks   = blocks;
    if (out_n_blocks) *out_n_blocks = n;
    return STM_OK;
}

stm_status eng_spill_chain_read(stm_btree_engine *eng,
                                 uint64_t head_paddr, uint64_t head_gen,
                                 const uint8_t head_csum[STM_BTNODE_CSUM_SIZE],
                                 uint64_t total_len,
                                 uint8_t **out_val, uint64_t **out_blocks,
                                 uint32_t *out_n_blocks)
{
    return spill_chain_walk(eng, head_paddr, head_gen, head_csum, total_len,
                            out_val, out_blocks, out_n_blocks);
}

stm_status eng_spill_chain_verify(stm_btree_engine *eng,
                                   uint64_t head_paddr, uint64_t head_gen,
                                   const uint8_t head_csum[STM_BTNODE_CSUM_SIZE],
                                   uint64_t total_len)
{
    return spill_chain_walk(eng, head_paddr, head_gen, head_csum, total_len,
                            NULL, NULL, NULL);
}

/* ========================================================================= */
/* Write.                                                                      */
/* ========================================================================= */

stm_status eng_node_write(stm_btree_engine *eng, eng_node *n, uint64_t gen)
{
    uint8_t *buf = malloc(STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;
    stm_status s;

    if (n->is_leaf) {
        /* Each on-disk leaf value is [tag : 1][payload]: an inline
         * value verbatim, or — when the entry carries an eng_spill
         * (leaf_sync_spill ran first) — the 72-byte indirection record.
         * Build the tagged blobs in one scratch buffer; point the codec
         * at it (the codec stores keys/values as opaque bytes). */
        stm_btnode_entry *ents = NULL;
        uint8_t          *vbuf = NULL;
        if (n->n_entries) {
            ents = malloc((size_t)n->n_entries * sizeof *ents);
            if (!ents) { free(buf); return STM_ENOMEM; }
            size_t vtot = 0;
            for (uint32_t i = 0; i < n->n_entries; i++)
                vtot += ENG_VAL_TAG_SIZE +
                        (n->entries[i].spill ? ENG_SPILL_INDIRECT_SIZE
                                             : n->entries[i].val_len);
            vbuf = malloc(vtot ? vtot : 1u);
            if (!vbuf) { free(ents); free(buf); return STM_ENOMEM; }
            uint8_t *vp = vbuf;
            for (uint32_t i = 0; i < n->n_entries; i++) {
                eng_entry *e = &n->entries[i];
                ents[i].key     = e->key;
                ents[i].key_len = e->key_len;
                ents[i].value   = vp;
                if (e->spill) {
                    *vp++ = ENG_VAL_SPILLED;
                    le64 rl = stm_store_le64(e->val_len);
                    memcpy(vp, rl.v, 8);
                    vp += 8;
                    encode_child_bptr(e->spill->blocks[0], ENG_SPILL_BPTR_KIND,
                                      e->spill->head_gen, e->spill->head_csum,
                                      vp);
                    vp += STM_BTNODE_CHILD_BPTR_SIZE;
                    ents[i].value_len = ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE;
                } else {
                    *vp++ = ENG_VAL_INLINE;
                    if (e->val_len) memcpy(vp, e->val, e->val_len);
                    vp += e->val_len;
                    ents[i].value_len = ENG_VAL_TAG_SIZE + e->val_len;
                }
            }
        }
        s = stm_btnode_leaf_encode(ents, n->n_entries, gen, eng->tree_id,
                                   buf, STM_BTREE_ENGINE_NODE_SIZE);
        free(ents);
        free(vbuf);
        if (s != STM_OK) { free(buf); return s; }
    } else {
        uint32_t np = n->n_pivots;
        uint32_t nc = np + 1u;
        stm_btnode_pivot *pivs = NULL;
        if (np) {
            pivs = malloc((size_t)np * sizeof *pivs);
            if (!pivs) { free(buf); return STM_ENOMEM; }
            for (uint32_t i = 0; i < np; i++) {
                pivs[i].key     = n->pivots[i].key;
                pivs[i].key_len = n->pivots[i].key_len;
            }
        }
        uint8_t *blob = malloc((size_t)nc * STM_BTNODE_CHILD_BPTR_SIZE);
        if (!blob) { free(pivs); free(buf); return STM_ENOMEM; }
        for (uint32_t i = 0; i < nc; i++) {
            uint8_t kind = n->children[i].is_leaf ? STM_BPTR_KIND_LEAF
                                                  : STM_BPTR_KIND_INTERNAL;
            encode_child_bptr(n->children[i].paddr, kind, n->children[i].gen,
                              n->children[i].csum,
                              blob + (size_t)i * STM_BTNODE_CHILD_BPTR_SIZE);
        }

        /* 9.8-BE (chunk 7b): NORMALISE the message buffer before
         * encoding — design 5.2's sort step. A pivot splice since the
         * messages were materialised can have re-routed targets, so
         * the in-memory array order is not trustworthy; the on-disk
         * order (target_child, seq) is normative. Stable insertion
         * sort IN PLACE (n->buf_msgs then mirrors the disk bytes) over
         * a per-message routing scratch; buf_count is bounded by the
         * region cap (~tens), so O(n^2) is noise.
         * R172 F1: the in-place sort is a buf_msgs MUTATION — legal
         * only on a node no wait-free reader can reach (readers hold
         * no rwlock; safety is COW, not exclusion). Holds today:
         * eng_node_write runs on dirty commit-path copies. BINDING on
         * chunk 8/9's mutators. */
        stm_btnode_msg *wm = NULL;
        if (n->buf_count) {
            uint32_t *route = malloc((size_t)n->buf_count * sizeof *route);
            wm = malloc((size_t)n->buf_count * sizeof *wm);
            if (!route || !wm) {
                free(route); free(wm);
                free(pivs); free(blob); free(buf);
                return STM_ENOMEM;
            }
            for (uint32_t i = 0; i < n->buf_count; i++)
                route[i] = eng_pivot_child_for(n, n->buf_msgs[i].key,
                                               n->buf_msgs[i].key_len);
            for (uint32_t i = 1; i < n->buf_count; i++) {
                eng_msg  mv = n->buf_msgs[i];
                uint32_t rv = route[i];
                uint32_t j  = i;
                while (j > 0 &&
                       (route[j - 1u] > rv ||
                        (route[j - 1u] == rv &&
                         n->buf_msgs[j - 1u].seq > mv.seq))) {
                    n->buf_msgs[j] = n->buf_msgs[j - 1u];
                    route[j]       = route[j - 1u];
                    j--;
                }
                n->buf_msgs[j] = mv;
                route[j]       = rv;
            }
            free(route);
            for (uint32_t i = 0; i < n->buf_count; i++) {
                wm[i].op        = n->buf_msgs[i].op;
                wm[i].seq       = n->buf_msgs[i].seq;
                wm[i].key       = n->buf_msgs[i].key;
                wm[i].key_len   = n->buf_msgs[i].key_len;
                wm[i].value     = n->buf_msgs[i].value;
                wm[i].value_len = n->buf_msgs[i].value_len;
            }
        }
        s = stm_btnode_internal_encode_msgs(pivs, np, blob,
                                       (size_t)nc * STM_BTNODE_CHILD_BPTR_SIZE,
                                       wm, n->buf_count,
                                       gen, eng->tree_id, n->seq_hw,
                                       buf, STM_BTREE_ENGINE_NODE_SIZE);
        free(wm);
        free(pivs);
        free(blob);
        if (s != STM_OK) { free(buf); return s; }
    }

    /* Reserve a fresh paddr — must precede encrypt so it can bind into
     * the AEAD nonce. On a failure after reserve, the reserved-but-
     * unwritten paddr is handed back via vt->free (deferred-free): it
     * was never durably referenced by any root, so reclaiming it is
     * safe and avoids a permanent paddr leak (this is distinct from the
     * documented impl-1b superseded-paddr boundary). */
    uint64_t paddr = 0;
    s = eng->vt->reserve(eng->vt_ctx, &paddr);
    if (s != STM_OK) { free(buf); return s; }

    s = stm_btree_node_encrypt(&eng->cx, paddr, gen, buf,
                               STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) {
        if (eng->vt->free) (void)eng->vt->free(eng->vt_ctx, paddr, gen);
        free(buf);
        return s;
    }

    uint8_t csum[STM_BTNODE_CSUM_SIZE];
    compute_ct_csum(buf, csum);                  /* over ciphertext */

    s = eng->vt->write(eng->vt_ctx, paddr, buf, STM_BTREE_ENGINE_NODE_SIZE);
    free(buf);
    if (s != STM_OK) {
        if (eng->vt->free) (void)eng->vt->free(eng->vt_ctx, paddr, gen);
        return s;
    }

    n->paddr = paddr;
    n->gen   = gen;
    memcpy(n->csum, csum, STM_BTNODE_CSUM_SIZE);
    n->dirty = false;
    return STM_OK;
}

/* ========================================================================= */
/* Read.                                                                       */
/* ========================================================================= */

typedef struct {
    stm_btree_engine *eng;
    eng_node         *node;
    stm_status        err;
} leaf_load_ctx;

static int leaf_load_cb(const void *key, size_t key_len,
                         const void *val, size_t val_len, void *ctx_)
{
    leaf_load_ctx *c = ctx_;
    const uint8_t *v = val;
    if (val_len < ENG_VAL_TAG_SIZE) { c->err = STM_ECORRUPT; return 1; }

    if (v[0] == ENG_VAL_INLINE) {
        stm_status s = eng_leaf_append(c->node, key, key_len,
                                       v + 1, val_len - 1u);
        if (s != STM_OK) { c->err = s; return 1; }
        return 0;
    }
    if (v[0] != ENG_VAL_SPILLED ||
        val_len != ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE) {
        c->err = STM_ECORRUPT;
        return 1;
    }

    /* Spilled: [tag][real_len : le64][head bptr : 64]. Materialise the
     * value from its spill chain, attach an eng_spill recording it. */
    le64 rl;
    memcpy(rl.v, v + 1, 8);
    uint64_t real_len = stm_load_le64(rl);
    uint64_t hp = 0, hg = 0;
    uint8_t  kind = 0;
    uint8_t  hc[STM_BTNODE_CSUM_SIZE];
    decode_child_bptr(v + 1 + 8, &hp, &kind, hc, &hg);

    uint8_t  *mval = NULL;
    uint64_t *blks = NULL;
    uint32_t  nblk = 0;
    stm_status s = eng_spill_chain_read(c->eng, hp, hg, hc, real_len,
                                        &mval, &blks, &nblk);
    if (s != STM_OK) { c->err = s; return 1; }

    eng_spill *sp = calloc(1, sizeof *sp);
    if (!sp) { free(mval); free(blks); c->err = STM_ENOMEM; return 1; }
    sp->dirty    = false;
    sp->blocks   = blks;
    sp->n_blocks = nblk;
    sp->head_gen = hg;
    memcpy(sp->head_csum, hc, STM_BTNODE_CSUM_SIZE);

    s = eng_leaf_append(c->node, key, key_len, mval, (size_t)real_len);
    free(mval);
    if (s != STM_OK) { free(blks); free(sp); c->err = s; return 1; }
    c->node->entries[c->node->n_entries - 1u].spill = sp;
    return 0;
}

typedef struct {
    eng_node  *node;
    stm_status err;
    /* 9.8-BE (chunk 7b): the message collector. Grown by doubling;
     * ownership transfers to node->buf_msgs on success; freed by the
     * read error path otherwise. */
    eng_msg   *msgs;
    uint32_t   n_msgs;
    uint32_t   msgs_cap;
} internal_load_ctx;

static int msg_load_cb(uint8_t op, uint64_t seq,
                        const void *key, size_t key_len,
                        const void *value, size_t value_len,
                        uint32_t idx, void *ctx_)
{
    internal_load_ctx *c = ctx_;
    (void)idx;
    if (c->n_msgs == c->msgs_cap) {
        uint32_t ncap = c->msgs_cap ? c->msgs_cap * 2u : 8u;
        eng_msg *g = realloc(c->msgs, (size_t)ncap * sizeof *g);
        if (!g) { c->err = STM_ENOMEM; return 1; }
        c->msgs = g;
        c->msgs_cap = ncap;
    }
    eng_msg *m = &c->msgs[c->n_msgs];
    memset(m, 0, sizeof *m);
    m->op  = op;
    m->seq = seq;
    if (key_len) {
        m->key = malloc(key_len);
        if (!m->key) { c->err = STM_ENOMEM; return 1; }
        memcpy(m->key, key, key_len);
    }
    m->key_len = (uint32_t)key_len;
    if (value_len) {
        m->value = malloc(value_len);
        if (!m->value) { free(m->key); m->key = NULL;
                         c->err = STM_ENOMEM; return 1; }
        memcpy(m->value, value, value_len);
    }
    m->value_len = (uint32_t)value_len;
    c->n_msgs++;
    return 0;
}

/*
 * Order validation at the trust boundary (9.8-BE chunk 7b): the wire
 * region must be ascending (target_child, seq), seq strictly
 * increasing within one child. The codec cannot validate this — it
 * cannot route keys — so it happens here, with the node's pivots fully
 * built. Disorder on disk mis-routes flushes (the #35 class), so it is
 * corruption, not tolerated-and-resorted.
 */
static stm_status msgs_validate_order(const eng_node *n,
                                       const eng_msg *msgs, uint32_t count)
{
    uint32_t prev_child = 0;
    uint64_t prev_seq   = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t child = eng_pivot_child_for(n, msgs[i].key,
                                             msgs[i].key_len);
        if (i > 0) {
            if (child < prev_child) return STM_ECORRUPT;
            if (child == prev_child && msgs[i].seq <= prev_seq)
                return STM_ECORRUPT;
        }
        prev_child = child;
        prev_seq   = msgs[i].seq;
    }
    return STM_OK;
}

static int pivot_load_cb(const void *key, size_t key_len,
                          uint32_t idx, void *ctx_)
{
    internal_load_ctx *c = ctx_;
    stm_status s = eng_internal_set_pivot(c->node, idx, key, key_len);
    if (s != STM_OK) { c->err = s; return 1; }
    return 0;
}

static int child_load_cb(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                          uint32_t idx, void *ctx_)
{
    internal_load_ctx *c = ctx_;
    uint64_t paddr = 0, gen = 0;
    uint8_t  kind  = 0;
    uint8_t  csum[STM_BTNODE_CSUM_SIZE];
    decode_child_bptr(bptr, &paddr, &kind, csum, &gen);

    bool is_leaf;
    if      (kind == STM_BPTR_KIND_LEAF)     is_leaf = true;
    else if (kind == STM_BPTR_KIND_INTERNAL) is_leaf = false;
    else { c->err = STM_ECORRUPT; return 1; }

    eng_child *ch = &c->node->children[idx];
    ch->mem     = NULL;
    ch->paddr   = paddr;
    ch->gen     = gen;
    ch->is_leaf = is_leaf;
    memcpy(ch->csum, csum, STM_BTNODE_CSUM_SIZE);
    return 0;
}

stm_status eng_node_read(stm_btree_engine *eng,
                          uint64_t paddr, uint64_t gen,
                          const uint8_t expected_csum[STM_BTNODE_CSUM_SIZE],
                          eng_node **out_node)
{
    uint8_t *buf = malloc(STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = eng->vt->read(eng->vt_ctx, paddr, buf,
                                 STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }

    /* Merkle gate before AEAD — a ciphertext byte-flip surfaces here. */
    s = check_merkle_link(buf, expected_csum);
    if (s != STM_OK) { free(buf); return s; }

    s = stm_btree_node_decrypt(&eng->cx, paddr, gen, buf,
                               STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }
    restore_plaintext_self_csum(buf);

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTREE_ENGINE_NODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    eng_node *n = NULL;
    if (info.kind == STM_BTNODE_KIND_LEAF) {
        n = eng_node_new_leaf();
        if (!n) { free(buf); return STM_ENOMEM; }
        leaf_load_ctx lc = { .eng = eng, .node = n, .err = STM_OK };
        s = stm_btnode_leaf_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   leaf_load_cb, &lc);
        if (s == STM_OK) s = lc.err;
        if (s != STM_OK) { eng_node_free(n); free(buf); return s; }
    } else {
        uint32_t np = info.n_entries;
        n = eng_node_new_internal_sized(np, np + 1u);
        if (!n) { free(buf); return STM_ENOMEM; }
        internal_load_ctx ic = { .node = n, .err = STM_OK };
        s = stm_btnode_internal_decode_msgs(buf, STM_BTREE_ENGINE_NODE_SIZE,
                                            NULL,
                                            pivot_load_cb, child_load_cb,
                                            msg_load_cb, &ic);
        if (s == STM_OK) s = ic.err;
        if (s != STM_OK) {
            eng_msg_array_free(ic.msgs, ic.n_msgs);
            eng_node_free(n); free(buf); return s;
        }
        n->n_pivots = np;
        /* 9.8-BE (chunk 7b): order validation needs the pivots built
         * (routing); attach the buffer only after it passes, so
         * eng_node_free never double-frees the collector's array. */
        s = msgs_validate_order(n, ic.msgs, ic.n_msgs);
        if (s != STM_OK) {
            eng_msg_array_free(ic.msgs, ic.n_msgs);
            eng_node_free(n); free(buf); return s;
        }
        n->buf_msgs  = ic.msgs;
        n->buf_count = ic.n_msgs;
    }
    free(buf);

    n->paddr  = paddr;
    n->gen    = gen;
    memcpy(n->csum, expected_csum, STM_BTNODE_CSUM_SIZE);
    n->dirty  = false;
    n->seq_hw = info.seq_hw;    /* 0 on leaves + pre-9.8 nodes */
    *out_node = n;
    return STM_OK;
}

/* ========================================================================= */
/* Verify — walk the on-disk subtree, Merkle + AEAD at every node.              */
/* ========================================================================= */

/*
 * Strict-ascending sort check for a node's entries / pivots. Merkle +
 * AEAD authenticate that a node was written by something holding the
 * metadata key, but a node with valid crypto and out-of-order keys
 * would silently mis-route the binary-search descents
 * (eng_leaf_lower_bound / eng_pivot_child_for) — fail-silent rather
 * than fail-closed. verify rejects it so structural corruption is
 * caught, not just bit-rot / substitution.
 */
typedef struct {
    uint8_t   *prev;
    size_t     prev_len;
    size_t     prev_cap;
    bool       have_prev;
    stm_status err;
} sortchk;

static int sortchk_step(sortchk *sc, const void *key, size_t key_len)
{
    if (sc->have_prev &&
        eng_key_cmp(sc->prev, sc->prev_len, key, key_len) >= 0) {
        sc->err = STM_ECORRUPT;          /* not strictly ascending */
        return 1;
    }
    if (key_len > sc->prev_cap) {
        uint8_t *g = realloc(sc->prev, key_len);
        if (!g) { sc->err = STM_ENOMEM; return 1; }
        sc->prev = g;
        sc->prev_cap = key_len;
    }
    if (key_len) memcpy(sc->prev, key, key_len);
    sc->prev_len  = key_len;
    sc->have_prev = true;
    return 0;
}

/* Leaf verify context: the key sort-check + the engine handle, so a
 * spilled value's chain can be walked. */
typedef struct {
    sortchk           sc;
    stm_btree_engine *eng;
    stm_status        err;
} verify_leaf_ctx;

static int verify_leaf_cb(const void *key, size_t key_len,
                           const void *val, size_t val_len, void *ctx_)
{
    verify_leaf_ctx *c = ctx_;
    if (sortchk_step(&c->sc, key, key_len) != 0) return 1;   /* sc.err set */

    const uint8_t *v = val;
    if (val_len < ENG_VAL_TAG_SIZE) { c->err = STM_ECORRUPT; return 1; }
    if (v[0] == ENG_VAL_SPILLED) {
        if (val_len != ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE) {
            c->err = STM_ECORRUPT; return 1;
        }
        le64 rl;
        memcpy(rl.v, v + 1, 8);
        uint64_t real_len = stm_load_le64(rl);
        uint64_t hp = 0, hg = 0;
        uint8_t  kind = 0;
        uint8_t  hc[STM_BTNODE_CSUM_SIZE];
        decode_child_bptr(v + 1 + 8, &hp, &kind, hc, &hg);
        stm_status s = eng_spill_chain_verify(c->eng, hp, hg, hc, real_len);
        if (s != STM_OK) { c->err = s; return 1; }
    } else if (v[0] != ENG_VAL_INLINE) {
        c->err = STM_ECORRUPT; return 1;
    }
    return 0;
}

typedef struct {
    uint64_t  *paddr;
    uint64_t  *gen;
    uint8_t   *csum;       /* nc × 32 */
    uint8_t   *kind;
    uint32_t   cap;
    uint32_t   n;
    sortchk    pchk;       /* pivot sort check */
    /* 9.8-BE-flush (chunk 8, R172 F2): pivots collected as BORROWED
     * pointers into the decode buffer (valid for the decode's
     * duration) so the message region's (target_child, seq) order is
     * validated here too, not only on the load path — a scrub must
     * reject what a load would. The wire layout puts pivots before
     * messages, so the array is complete before the first msg cb. */
    eng_pivot *pivs;
    uint32_t   np;
    uint32_t   np_cap;
    uint32_t   prev_child;
    uint64_t   prev_seq;
    bool       have_msg;
    stm_status err;
} verify_child_ctx;

static int verify_pivot_cb(const void *key, size_t key_len,
                            uint32_t idx, void *ctx_)
{
    verify_child_ctx *c = ctx_;
    if (idx >= c->np_cap) { c->err = STM_ECORRUPT; return 1; }
    c->pivs[idx].key     = (uint8_t *)(uintptr_t)key;   /* borrowed */
    c->pivs[idx].key_len = (uint32_t)key_len;
    if (idx + 1u > c->np) c->np = idx + 1u;
    return sortchk_step(&c->pchk, key, key_len);
}

/* The load path's msgs_validate_order, streamed: route each message
 * through a stack shell over the collected pivots (the SAME router a
 * descent uses — no reimplementation to drift) and require ascending
 * (target_child, seq), seq strictly increasing within one child. */
static int verify_msg_cb(uint8_t op, uint64_t seq,
                          const void *key, size_t key_len,
                          const void *value, size_t value_len,
                          uint32_t idx, void *ctx_)
{
    (void)op; (void)value; (void)value_len; (void)idx;
    verify_child_ctx *c = ctx_;
    eng_node shell;
    memset(&shell, 0, sizeof shell);
    shell.pivots   = c->pivs;
    shell.n_pivots = c->np;
    uint32_t child = eng_pivot_child_for(&shell, key, key_len);
    if (c->have_msg &&
        (child < c->prev_child ||
         (child == c->prev_child && seq <= c->prev_seq))) {
        c->err = STM_ECORRUPT;
        return 1;
    }
    c->prev_child = child;
    c->prev_seq   = seq;
    c->have_msg   = true;
    return 0;
}

static int verify_child_cb(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                            uint32_t idx, void *ctx_)
{
    verify_child_ctx *c = ctx_;
    (void)idx;
    if (c->n >= c->cap) { c->err = STM_ECORRUPT; return 1; }
    uint8_t csum[STM_BTNODE_CSUM_SIZE];
    decode_child_bptr(bptr, &c->paddr[c->n], &c->kind[c->n], csum,
                      &c->gen[c->n]);
    memcpy(&c->csum[(size_t)c->n * STM_BTNODE_CSUM_SIZE], csum,
           STM_BTNODE_CSUM_SIZE);
    c->n++;
    return 0;
}

stm_status eng_verify_subtree(stm_btree_engine *eng,
                               uint64_t paddr, uint64_t gen,
                               const uint8_t expected_csum[STM_BTNODE_CSUM_SIZE],
                               uint32_t depth)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    uint8_t *buf = malloc(STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = eng->vt->read(eng->vt_ctx, paddr, buf,
                                 STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }
    s = check_merkle_link(buf, expected_csum);
    if (s != STM_OK) { free(buf); return s; }
    s = stm_btree_node_decrypt(&eng->cx, paddr, gen, buf,
                               STM_BTREE_ENGINE_NODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }
    restore_plaintext_self_csum(buf);

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTREE_ENGINE_NODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    if (info.kind == STM_BTNODE_KIND_LEAF) {
        /* Decode validates entry boundaries; verify_leaf_cb additionally
         * rejects out-of-order entries and walks each spilled value's
         * chain (Merkle + AEAD at every spill block). */
        verify_leaf_ctx vlc = { .eng = eng };
        s = stm_btnode_leaf_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   verify_leaf_cb, &vlc);
        if (s == STM_OK) s = vlc.sc.err;
        if (s == STM_OK) s = vlc.err;
        free(vlc.sc.prev);
        free(buf);
        return s;
    }

    /* Internal: collect child links, free the buffer, then recurse. */
    uint32_t nc = info.n_entries + 1u;
    verify_child_ctx cc = { 0 };
    cc.paddr = calloc(nc, sizeof *cc.paddr);
    cc.gen   = calloc(nc, sizeof *cc.gen);
    cc.kind  = calloc(nc, sizeof *cc.kind);
    cc.csum  = calloc((size_t)nc * STM_BTNODE_CSUM_SIZE, 1);
    cc.pivs  = calloc(info.n_entries ? info.n_entries : 1u, sizeof *cc.pivs);
    cc.np_cap = info.n_entries;
    cc.cap   = nc;
    if (!cc.paddr || !cc.gen || !cc.kind || !cc.csum || !cc.pivs) {
        free(cc.paddr); free(cc.gen); free(cc.kind); free(cc.csum);
        free(cc.pivs);
        free(buf);
        return STM_ENOMEM;
    }

    /* 9.8-BE: buffer-aware decode. The message region's structure is
     * validated by the codec walk; the (target_child, seq) ORDER gate
     * runs here too (chunk 8, R172 F2) via verify_msg_cb over the
     * borrowed pivot array — so scrub rejects exactly what a load
     * (eng_node_read::msgs_validate_order) would. */
    s = stm_btnode_internal_decode_msgs(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   verify_pivot_cb, verify_child_cb,
                                   verify_msg_cb, &cc);
    if (s == STM_OK) s = cc.pchk.err;          /* pivots strictly sorted */
    if (s == STM_OK) s = cc.err;
    free(cc.pchk.prev);
    free(cc.pivs);
    free(buf);

    for (uint32_t i = 0; s == STM_OK && i < cc.n; i++) {
        if (cc.kind[i] != STM_BPTR_KIND_LEAF &&
            cc.kind[i] != STM_BPTR_KIND_INTERNAL) {
            s = STM_ECORRUPT;
            break;
        }
        s = eng_verify_subtree(eng, cc.paddr[i], cc.gen[i],
                               &cc.csum[(size_t)i * STM_BTNODE_CSUM_SIZE],
                               depth + 1u);
    }

    free(cc.paddr);
    free(cc.gen);
    free(cc.kind);
    free(cc.csum);
    return s;
}
