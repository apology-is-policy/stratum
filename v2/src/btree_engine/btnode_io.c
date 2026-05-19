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
/* Write.                                                                      */
/* ========================================================================= */

stm_status eng_node_write(stm_btree_engine *eng, eng_node *n, uint64_t gen)
{
    uint8_t *buf = malloc(STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;
    stm_status s;

    if (n->is_leaf) {
        stm_btnode_entry *ents = NULL;
        if (n->n_entries) {
            ents = malloc((size_t)n->n_entries * sizeof *ents);
            if (!ents) { free(buf); return STM_ENOMEM; }
            for (uint32_t i = 0; i < n->n_entries; i++) {
                ents[i].key       = n->entries[i].key;
                ents[i].key_len   = n->entries[i].key_len;
                ents[i].value     = n->entries[i].val;
                ents[i].value_len = n->entries[i].val_len;
            }
        }
        s = stm_btnode_leaf_encode(ents, n->n_entries, gen, eng->tree_id,
                                   buf, STM_BTREE_ENGINE_NODE_SIZE);
        free(ents);
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
        s = stm_btnode_internal_encode(pivs, np, blob,
                                       (size_t)nc * STM_BTNODE_CHILD_BPTR_SIZE,
                                       gen, eng->tree_id,
                                       buf, STM_BTREE_ENGINE_NODE_SIZE);
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
    eng_node  *node;
    stm_status err;
} leaf_load_ctx;

static int leaf_load_cb(const void *key, size_t key_len,
                         const void *val, size_t val_len, void *ctx_)
{
    leaf_load_ctx *c = ctx_;
    stm_status s = eng_leaf_append(c->node, key, key_len, val, val_len);
    if (s != STM_OK) { c->err = s; return 1; }
    return 0;
}

typedef struct {
    eng_node  *node;
    stm_status err;
} internal_load_ctx;

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
        leaf_load_ctx lc = { .node = n, .err = STM_OK };
        s = stm_btnode_leaf_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   leaf_load_cb, &lc);
        if (s == STM_OK) s = lc.err;
        if (s != STM_OK) { eng_node_free(n); free(buf); return s; }
    } else {
        uint32_t np = info.n_entries;
        n = eng_node_new_internal_sized(np, np + 1u);
        if (!n) { free(buf); return STM_ENOMEM; }
        internal_load_ctx ic = { .node = n, .err = STM_OK };
        s = stm_btnode_internal_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                       pivot_load_cb, child_load_cb, &ic);
        if (s == STM_OK) s = ic.err;
        if (s != STM_OK) { eng_node_free(n); free(buf); return s; }
        n->n_pivots = np;
    }
    free(buf);

    n->paddr = paddr;
    n->gen   = gen;
    memcpy(n->csum, expected_csum, STM_BTNODE_CSUM_SIZE);
    n->dirty = false;
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

static int verify_leaf_cb(const void *key, size_t key_len,
                           const void *val, size_t val_len, void *ctx_)
{
    (void)val; (void)val_len;
    return sortchk_step((sortchk *)ctx_, key, key_len);
}

typedef struct {
    uint64_t  *paddr;
    uint64_t  *gen;
    uint8_t   *csum;       /* nc × 32 */
    uint8_t   *kind;
    uint32_t   cap;
    uint32_t   n;
    sortchk    pchk;       /* pivot sort check */
    stm_status err;
} verify_child_ctx;

static int verify_pivot_cb(const void *key, size_t key_len,
                            uint32_t idx, void *ctx_)
{
    (void)idx;
    verify_child_ctx *c = ctx_;
    return sortchk_step(&c->pchk, key, key_len);
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
         * rejects out-of-order entries. */
        sortchk sc = { 0 };
        s = stm_btnode_leaf_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   verify_leaf_cb, &sc);
        if (s == STM_OK) s = sc.err;
        free(sc.prev);
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
    cc.cap   = nc;
    if (!cc.paddr || !cc.gen || !cc.kind || !cc.csum) {
        free(cc.paddr); free(cc.gen); free(cc.kind); free(cc.csum);
        free(buf);
        return STM_ENOMEM;
    }

    s = stm_btnode_internal_decode(buf, STM_BTREE_ENGINE_NODE_SIZE, NULL,
                                   verify_pivot_cb, verify_child_cb, &cc);
    if (s == STM_OK) s = cc.pchk.err;          /* pivots strictly sorted */
    if (s == STM_OK) s = cc.err;
    free(cc.pchk.prev);
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
