/* SPDX-License-Identifier: ISC */
/*
 * Tree serialize / deserialize driver (Phase 3 chunk 5c).
 *
 * Algorithm (serialize):
 *   1. Scan the in-RAM tree to collect every (key, value) pair in key
 *      order.
 *   2. Partition the collected entries into leaf-sized chunks, each
 *      ≤ STM_BTNODE_PAYLOAD_MAX bytes.
 *   3. For each leaf chunk: reserve a node paddr via the vtable,
 *      encode with stm_btnode_leaf_encode, write.
 *   4. If > 1 leaf, build a single internal node whose pivots are the
 *      first-key of each leaf after the first, and whose N+1 children
 *      are the leaf paddrs. Chunk 5c caps depth at 2 levels —
 *      STM_ENOTSUPPORTED if the internal encoding would exceed
 *      STM_BTNODE_PAYLOAD_MAX.
 *   5. Return the root paddr.
 *
 * Algorithm (deserialize):
 *   1. Read the root node.
 *   2. If LEAF: stm_btnode_leaf_decode with a callback that inserts
 *      into t.
 *   3. If INTERNAL: decode children; for each, recursively read as a
 *      LEAF. (MVP caps at two levels.)
 *
 * Child encoding:
 *   Children in internal nodes are 64-byte blobs laid out as the
 *   packed form of an stm_bptr — first 8 bytes are the paddr (LE u64),
 *   then kind (1 byte) + flags (1 byte) + 6 bytes pad + 32 bytes
 *   csum (populated in P4-1 with the child node's BLAKE3 self-csum
 *   so internal nodes carry the Merkle chain) + 16 bytes reserved.
 *   Parallels the stm_bptr layout in super.h exactly.
 */

#include <stratum/btree.h>
#include <stratum/btnode.h>
#include <stratum/btree_store.h>
#include <stratum/hash.h>
#include <stratum/super.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* P4-3b: size of the ciphertext region in an encrypted node image.
 * The trailing STM_BTNODE_CSUM_SIZE bytes hold the AEAD tag; bp_csum
 * covers ONLY the ciphertext region, not the tag. */
#define CT_LEN (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)

/* ========================================================================= */
/* Collector: walk the in-RAM tree via scan, store entries in an              */
/* owned, order-preserving buffer.                                            */
/* ========================================================================= */

typedef struct {
    uint8_t *key;
    size_t   key_len;
    uint8_t *value;
    size_t   value_len;
} coll_entry;

typedef struct {
    coll_entry *entries;
    size_t      n_entries;
    size_t      cap;
    stm_status  err;       /* first encountered error */
} collector;

static int scan_collect_cb(const void *key, size_t key_len,
                            const void *value, size_t value_len, void *ctx_)
{
    collector *c = ctx_;
    if (c->err != STM_OK) return 1;

    if (c->n_entries == c->cap) {
        size_t new_cap = c->cap ? c->cap * 2 : 64;
        coll_entry *newp = realloc(c->entries, new_cap * sizeof *newp);
        if (!newp) { c->err = STM_ENOMEM; return 1; }
        c->entries = newp;
        c->cap = new_cap;
    }

    coll_entry *e = &c->entries[c->n_entries];
    e->key       = NULL;
    e->key_len   = key_len;
    e->value     = NULL;
    e->value_len = value_len;

    if (key_len) {
        e->key = malloc(key_len);
        if (!e->key) { c->err = STM_ENOMEM; return 1; }
        memcpy(e->key, key, key_len);
    }
    if (value_len) {
        e->value = malloc(value_len);
        if (!e->value) {
            free(e->key);
            c->err = STM_ENOMEM;
            return 1;
        }
        memcpy(e->value, value, value_len);
    }

    c->n_entries++;
    return 0;
}

static void collector_free(collector *c)
{
    if (!c->entries) return;
    for (size_t i = 0; i < c->n_entries; i++) {
        free(c->entries[i].key);
        free(c->entries[i].value);
    }
    free(c->entries);
    c->entries = NULL;
    c->n_entries = 0;
    c->cap = 0;
}

/* ========================================================================= */
/* Leaf partitioning.                                                         */
/* ========================================================================= */

/*
 * Partition the collected entries into leaf chunks, each ≤ PAYLOAD_MAX.
 * Writes out_starts[] (one index per leaf, length out_n_leaves + 1 so
 * out_starts[L] is a sentinel "one past the end"). Caller owns the
 * out_starts buffer; pass a reasonable initial capacity.
 *
 * Returns STM_ERANGE if any single entry is larger than PAYLOAD_MAX.
 */
static stm_status partition_leaves(const coll_entry *entries, size_t n,
                                     size_t **out_starts,
                                     size_t *out_n_leaves)
{
    /* Worst case: one leaf per entry. Bound allocation accordingly. */
    size_t cap = (n == 0) ? 2 : (n + 1);
    size_t *starts = calloc(cap, sizeof *starts);
    if (!starts) return STM_ENOMEM;

    size_t n_leaves = 0;
    starts[0] = 0;

    if (n == 0) {
        /* One empty leaf. */
        n_leaves = 1;
        starts[1] = 0;
        *out_starts   = starts;
        *out_n_leaves = n_leaves;
        return STM_OK;
    }

    size_t leaf_bytes = 0;
    size_t leaf_start = 0;
    for (size_t i = 0; i < n; i++) {
        size_t e_bytes = STM_BTNODE_ENTRY_HDR_SIZE +
                         entries[i].key_len + entries[i].value_len;
        if (e_bytes > STM_BTNODE_PAYLOAD_MAX) {
            free(starts);
            return STM_ERANGE;
        }

        if (leaf_bytes + e_bytes > STM_BTNODE_PAYLOAD_MAX) {
            /* Close current leaf, start new. */
            starts[n_leaves + 1] = i;
            n_leaves++;
            leaf_start = i;
            leaf_bytes = 0;
        }
        leaf_bytes += e_bytes;
        (void)leaf_start;
    }
    /* Close the last leaf. */
    starts[n_leaves + 1] = n;
    n_leaves++;

    *out_starts   = starts;
    *out_n_leaves = n_leaves;
    return STM_OK;
}

/* ========================================================================= */
/* Child bptr encoding.                                                       */
/* ========================================================================= */

/* Pack the 64 bytes of an stm_bptr pointing at `paddr` with `kind`.
 * Csum carries the child node's BLAKE3-256 self-csum (P4-1 —
 * Merkle chain). Reserved regions zeroed. */
static void encode_child_bptr(uint64_t paddr, stm_bptr_kind kind,
                                const uint8_t child_csum[32],
                                uint8_t out[STM_BTNODE_CHILD_BPTR_SIZE])
{
    memset(out, 0, STM_BTNODE_CHILD_BPTR_SIZE);
    stm_bptr bp = { 0 };
    bp.bp_paddr = stm_store_le64(paddr);
    bp.bp_kind  = (uint8_t)kind;
    if (child_csum) memcpy(bp.bp_csum, child_csum, 32);
    memcpy(out, &bp, sizeof bp);
}

static void decode_child_bptr(const uint8_t in[STM_BTNODE_CHILD_BPTR_SIZE],
                                uint64_t *out_paddr, uint8_t *out_kind,
                                uint8_t out_csum[32])
{
    stm_bptr bp;
    memcpy(&bp, in, sizeof bp);
    *out_paddr = stm_load_le64(bp.bp_paddr);
    *out_kind  = bp.bp_kind;
    if (out_csum) memcpy(out_csum, bp.bp_csum, 32);
}

/* P4-3b: Compute bp_csum for an on-disk encrypted node image —
 * BLAKE3 over the ciphertext region (first CT_LEN bytes). The AEAD
 * tag in the trailing STM_BTNODE_CSUM_SIZE bytes is NOT included;
 * tag integrity is provided by the AEAD decrypt path, not the Merkle
 * chain. */
static inline void compute_bp_csum(const uint8_t *buf, uint8_t out[32])
{
    stm_blake3_hash h;
    stm_blake3(buf, CT_LEN, &h);
    memcpy(out, h.bytes, 32);
}

/* ========================================================================= */
/* Leaf emission.                                                             */
/* ========================================================================= */

/* Emit one leaf: encode plaintext → reserve paddr → AEAD-encrypt in
 * place → compute bp_csum over ciphertext → write.
 *
 * P4-3b ordering: reserve MUST precede encrypt so the paddr is known
 * and can be bound into the AEAD nonce. bp_csum MUST be computed
 * AFTER encryption (it hashes the ciphertext).
 *
 * On encryption failure the scratch buffer is in undefined state; we
 * don't call vt->write, so no tampered image reaches disk. The paddr
 * was already reserved — it becomes a burned paddr for this commit,
 * reclaimed on the NEXT commit's sweep if the caller reports the
 * failure upward (stm_alloc_commit unwinds on any error). */
static stm_status emit_leaf(const coll_entry *entries, size_t lo, size_t hi,
                              uint64_t gen, uint64_t tree_id,
                              const stm_btree_store_vtable *vt, void *ctx,
                              const stm_btree_crypt_ctx *cx,
                              uint8_t *scratch,
                              uint64_t *out_paddr,
                              uint8_t out_csum[32])
{
    /* Build stm_btnode_entry array pointing at collector's storage. */
    size_t n = hi - lo;
    stm_btnode_entry *nodes = NULL;
    if (n > 0) {
        nodes = calloc(n, sizeof *nodes);
        if (!nodes) return STM_ENOMEM;
        for (size_t i = 0; i < n; i++) {
            nodes[i].key       = entries[lo + i].key;
            nodes[i].key_len   = entries[lo + i].key_len;
            nodes[i].value     = entries[lo + i].value;
            nodes[i].value_len = entries[lo + i].value_len;
        }
    }

    stm_status s = stm_btnode_leaf_encode(nodes, (uint32_t)n, gen, tree_id,
                                            scratch, STM_BTNODE_SIZE);
    free(nodes);
    if (s != STM_OK) return s;

    s = vt->reserve(ctx, out_paddr);
    if (s != STM_OK) return s;

    s = stm_btree_node_encrypt(cx, *out_paddr, gen, scratch);
    if (s != STM_OK) return s;

    compute_bp_csum(scratch, out_csum);

    return vt->write(ctx, *out_paddr, scratch, STM_BTNODE_SIZE);
}

/* ========================================================================= */
/* Internal emission.                                                         */
/* ========================================================================= */

static stm_status emit_internal(const stm_btnode_pivot *pivots, uint32_t np,
                                  const uint8_t *children, size_t children_len,
                                  uint64_t gen, uint64_t tree_id,
                                  const stm_btree_store_vtable *vt, void *ctx,
                                  const stm_btree_crypt_ctx *cx,
                                  uint8_t *scratch,
                                  uint64_t *out_paddr,
                                  uint8_t out_csum[32])
{
    stm_status s = stm_btnode_internal_encode(pivots, np,
                                                children, children_len,
                                                gen, tree_id,
                                                scratch, STM_BTNODE_SIZE);
    if (s != STM_OK) return s;

    s = vt->reserve(ctx, out_paddr);
    if (s != STM_OK) return s;

    s = stm_btree_node_encrypt(cx, *out_paddr, gen, scratch);
    if (s != STM_OK) return s;

    compute_bp_csum(scratch, out_csum);

    return vt->write(ctx, *out_paddr, scratch, STM_BTNODE_SIZE);
}

/* ========================================================================= */
/* Public: serialize.                                                         */
/* ========================================================================= */

stm_status stm_btree_store_serialize(stm_btree_mt *t,
                                       uint64_t gen, uint64_t tree_id,
                                       const stm_btree_store_vtable *vt,
                                       void *vt_ctx,
                                       const stm_btree_crypt_ctx *cx,
                                       uint64_t *out_root_paddr,
                                       uint8_t  out_root_csum[32])
{
    if (!t || !vt || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    if (!vt->reserve || !vt->write)   return STM_EINVAL;
    /* P4-3b: encryption is mandatory. A NULL cx would cause the
     * encrypt helper to return STM_EINVAL anyway, but checking up
     * front gives a single crisp error point. */
    if (!cx || !cx->metadata_key) return STM_EINVAL;

    /* Scratch buffer used for both leaf and internal encode. */
    uint8_t *scratch = malloc(STM_BTNODE_SIZE);
    if (!scratch) return STM_ENOMEM;

    /* Collect all entries via scan. */
    collector coll = { 0 };
    stm_status s = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                      scan_collect_cb, &coll);
    if (s == STM_OK && coll.err != STM_OK) s = coll.err;
    if (s != STM_OK) { collector_free(&coll); free(scratch); return s; }

    /* Partition into leaves. */
    size_t *starts   = NULL;
    size_t  n_leaves = 0;
    s = partition_leaves(coll.entries, coll.n_entries, &starts, &n_leaves);
    if (s != STM_OK) {
        collector_free(&coll); free(scratch); return s;
    }

    /* Emit leaves. Record paddrs, csums, and per-leaf first keys. */
    uint64_t *leaf_paddrs = calloc(n_leaves, sizeof *leaf_paddrs);
    uint8_t  *leaf_csums  = calloc(n_leaves, 32);   /* 32 bytes each */
    if (!leaf_paddrs || !leaf_csums) {
        free(leaf_paddrs); free(leaf_csums);
        free(starts); collector_free(&coll); free(scratch);
        return STM_ENOMEM;
    }

    for (size_t i = 0; i < n_leaves; i++) {
        s = emit_leaf(coll.entries, starts[i], starts[i + 1],
                      gen, tree_id, vt, vt_ctx, cx,
                      scratch, &leaf_paddrs[i], &leaf_csums[i * 32]);
        if (s != STM_OK) goto cleanup;
    }

    /* Single leaf → its paddr IS the root, and its csum IS the root csum. */
    if (n_leaves == 1) {
        *out_root_paddr = leaf_paddrs[0];
        memcpy(out_root_csum, &leaf_csums[0], 32);
        s = STM_OK;
        goto cleanup;
    }

    /* Multi-leaf: build the root internal. Pivots are the first key of
     * leaves 1..n_leaves-1. (Leaf 0 is below every pivot.) */
    uint32_t n_pivots = (uint32_t)(n_leaves - 1);
    stm_btnode_pivot *pivots = calloc(n_pivots, sizeof *pivots);
    uint8_t         *children = calloc(n_leaves, STM_BTNODE_CHILD_BPTR_SIZE);
    if (!pivots || !children) {
        free(pivots); free(children);
        s = STM_ENOMEM; goto cleanup;
    }

    for (uint32_t i = 0; i < n_pivots; i++) {
        /* starts[i+1] is the first entry of leaf i+1. Use its key as
         * pivot[i]. */
        size_t first = starts[i + 1];
        pivots[i].key     = coll.entries[first].key;
        pivots[i].key_len = coll.entries[first].key_len;
    }
    for (size_t i = 0; i < n_leaves; i++) {
        encode_child_bptr(leaf_paddrs[i], STM_BPTR_KIND_LEAF,
                          &leaf_csums[i * 32],
                          children + i * STM_BTNODE_CHILD_BPTR_SIZE);
    }

    /* Check internal fits in PAYLOAD_MAX. If not → chunk 5 MVP caps
     * at two levels; bigger trees need a future multi-level pass. */
    size_t internal_bytes = stm_btnode_internal_encoded_bytes(pivots, n_pivots);
    if (internal_bytes > STM_BTNODE_PAYLOAD_MAX) {
        free(pivots); free(children);
        s = STM_ENOTSUPPORTED; goto cleanup;
    }

    uint64_t root_paddr = 0;
    s = emit_internal(pivots, n_pivots,
                      children, (size_t)n_leaves * STM_BTNODE_CHILD_BPTR_SIZE,
                      gen, tree_id, vt, vt_ctx, cx,
                      scratch, &root_paddr, out_root_csum);
    free(pivots);
    free(children);
    if (s != STM_OK) goto cleanup;

    *out_root_paddr = root_paddr;
    s = STM_OK;

cleanup:
    free(leaf_csums);
    free(leaf_paddrs);
    free(starts);
    collector_free(&coll);
    free(scratch);
    return s;
}

/* ========================================================================= */
/* Public: deserialize.                                                       */
/* ========================================================================= */

typedef struct {
    stm_btree_mt *tree;
    /* R7c P2-6: track the last key seen to reject out-of-order or
     * duplicate-key entries. A tampered leaf that inserted duplicates
     * would silently overwrite via upsert, masking corruption. */
    uint8_t      *prev_key;
    size_t        prev_key_len;
    size_t        prev_key_cap;
    stm_status    err;
} insert_ctx;

/* Byte-string lex compare, matching stm_btree's ordering. Returns
 * < 0, 0, > 0. */
static int keys_cmp(const void *a, size_t alen,
                    const void *b, size_t blen)
{
    size_t m = alen < blen ? alen : blen;
    int r = memcmp(a, b, m);
    if (r != 0) return r;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int insert_cb(const void *key, size_t key_len,
                      const void *value, size_t value_len, void *ctx_)
{
    insert_ctx *c = ctx_;

    /* Sort-order check: new key must be strictly greater than the
     * last one we saw. Same-leaf duplicates and cross-leaf overlap
     * (a following leaf's first key ≤ a previous leaf's last key)
     * both surface here. */
    if (c->prev_key_len > 0) {
        int cmp = keys_cmp(c->prev_key, c->prev_key_len, key, key_len);
        if (cmp >= 0) { c->err = STM_ECORRUPT; return 1; }
    }

    /* Remember this key for the next comparison. Grow buffer as
     * needed. */
    if (key_len > c->prev_key_cap) {
        size_t new_cap = key_len * 2u;
        uint8_t *grew = realloc(c->prev_key, new_cap);
        if (!grew) { c->err = STM_ENOMEM; return 1; }
        c->prev_key     = grew;
        c->prev_key_cap = new_cap;
    }
    if (key_len) memcpy(c->prev_key, key, key_len);
    c->prev_key_len = key_len;

    stm_status s = stm_btree_mt_insert(c->tree, key, key_len, value, value_len);
    if (s != STM_OK) { c->err = s; return 1; }
    return 0;
}

static stm_status deserialize_leaf(stm_btree_mt *t, const uint8_t *buf,
                                     insert_ctx *ic)
{
    stm_status s = stm_btnode_leaf_decode(buf, STM_BTNODE_SIZE,
                                            NULL, insert_cb, ic);
    (void)t;
    if (s != STM_OK) return s;
    return ic->err;
}

typedef struct {
    /* Deserialization needs a mutable list of child paddrs. Collect
     * children first, then process them outside the callback so
     * reentrant vtable calls don't nest. */
    uint64_t *child_paddrs;
    uint8_t  *child_kinds;
    uint8_t  *child_csums;        /* 32 bytes per child (P4-1)   */
    uint32_t  n_children;
    uint32_t  cap;
    stm_status err;
} child_collect;

static int child_record_cb(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                             uint32_t idx, void *ctx_)
{
    (void)idx;
    child_collect *c = ctx_;
    if (c->err != STM_OK) return 1;
    if (c->n_children == c->cap) { c->err = STM_EOVERFLOW; return 1; }

    uint64_t paddr = 0;
    uint8_t  kind  = 0;
    uint8_t  csum[32];
    decode_child_bptr(bptr, &paddr, &kind, csum);
    c->child_paddrs[c->n_children] = paddr;
    c->child_kinds [c->n_children] = kind;
    memcpy(&c->child_csums[c->n_children * 32], csum, 32);
    c->n_children++;
    return 0;
}

/* P4-3b: verifies the Merkle LINK by computing BLAKE3 over the
 * ciphertext region and comparing against the parent bptr /
 * uberblock's recorded bp_csum.
 *
 * Pre-P4-3b this function compared the trailing 32 bytes of the node
 * against `expected`; that worked because the trailing bytes held the
 * plaintext BLAKE3 self-csum. Post-P4-3b those bytes hold the AEAD
 * tag — a separate integrity primitive — so we hash the ciphertext
 * region explicitly.
 *
 * Running BEFORE AEAD decryption means a byte flip in the ciphertext
 * is caught here at the Merkle layer before consuming AEAD decrypt's
 * (constant-cost but still wasted) work. Tampered tag alone is
 * caught by AEAD decrypt downstream.
 *
 * R8-P2-3 rationale still holds: self-csum (now = Merkle csum =
 * BLAKE3 of ciphertext) catches bit rot; Merkle match catches
 * substitution of a well-formed alternative node at the victim
 * paddr. AEAD adds a third layer — even a substituted well-formed
 * node matching `expected` under the same key won't match the AEAD
 * tag unless the attacker also has the key. */
static inline stm_status check_merkle_link(const uint8_t *buf,
                                             const uint8_t expected[32])
{
    if (!expected) return STM_OK;
    uint8_t actual[32];
    compute_bp_csum(buf, actual);
    if (memcmp(actual, expected, 32) != 0) return STM_ECORRUPT;
    return STM_OK;
}

/* After stm_btree_node_decrypt, buf[0..CT_LEN) is plaintext but
 * buf[CT_LEN..SIZE) still holds the AEAD tag (decrypt only writes
 * the first CT_LEN bytes). btnode_verify_csum — called from every
 * leaf/internal decode path — expects the trailing 32 bytes to be
 * the plaintext self-csum (BLAKE3 over the first CT_LEN bytes with
 * those last 32 zeroed). We recompute and write it so the
 * downstream decoders pass their self-csum check.
 *
 * Redundant with AEAD+Merkle (both already verify integrity of the
 * plaintext-we-are-about-to-trust), but avoids touching btnode.c —
 * keeps self-csum semantics single-sourced in btnode. */
static void restore_plaintext_self_csum(uint8_t *buf)
{
    uint8_t saved[32];
    memcpy(saved, buf + CT_LEN, 32);
    memset(buf + CT_LEN, 0, 32);

    stm_blake3_hash h;
    stm_blake3(buf, CT_LEN, &h);
    memcpy(buf + CT_LEN, h.bytes, 32);
    (void)saved;   /* AEAD tag no longer needed; we won't re-encrypt */
}

stm_status stm_btree_store_deserialize(stm_btree_mt *t, uint64_t root_paddr,
                                         uint64_t gen,
                                         const uint8_t expected_root_csum[32],
                                         const stm_btree_store_vtable *vt,
                                         void *vt_ctx,
                                         const stm_btree_crypt_ctx *cx)
{
    if (!t || !vt)                          return STM_EINVAL;
    if (!vt->read)                          return STM_EINVAL;
    if (!expected_root_csum)                return STM_EINVAL;
    /* P4-3b: decryption is mandatory. Symmetric to serialize's check. */
    if (!cx || !cx->metadata_key)           return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    /* Read root. */
    stm_status s = vt->read(vt_ctx, root_paddr, buf, STM_BTNODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }

    /* P4-1 + P4-3b Merkle gate: recompute BLAKE3 over the ciphertext
     * region and compare against the caller's expected value (from
     * ub_alloc_root.bp_csum or a parent internal's bptr).
     * Both checks are needed: Merkle-match catches substitution of a
     * well-formed stale or attacker-controlled node (and detects byte
     * tamper before we bother calling AEAD). AEAD decrypt below
     * catches the rarer case where attacker somehow produced a
     * matching BLAKE3 with a tampered AEAD tag — not possible without
     * the metadata key, but defense-in-depth. */
    s = check_merkle_link(buf, expected_root_csum);
    if (s != STM_OK) { free(buf); return s; }

    /* P4-3b: decrypt in place. A tag-verify failure aborts with
     * STM_EBADTAG — surfaced to the caller as a read failure. */
    s = stm_btree_node_decrypt(cx, root_paddr, gen, buf);
    if (s != STM_OK) { free(buf); return s; }
    restore_plaintext_self_csum(buf);

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    if (info.kind == STM_BTNODE_KIND_LEAF) {
        insert_ctx ic = { .tree = t };
        s = deserialize_leaf(t, buf, &ic);
        free(buf);
        free(ic.prev_key);
        return s;
    }

    /* INTERNAL root. Collect child paddrs + csums, then iterate. MVP
     * caps at one internal level → children must all be LEAF. */
    uint32_t cap = info.n_entries + 1u;   /* = n_pivots + 1 */
    child_collect cc = { 0 };
    cc.child_paddrs = calloc(cap, sizeof *cc.child_paddrs);
    cc.child_kinds  = calloc(cap, sizeof *cc.child_kinds);
    cc.child_csums  = calloc((size_t)cap * 32u, sizeof *cc.child_csums);
    cc.cap          = cap;
    if (!cc.child_paddrs || !cc.child_kinds || !cc.child_csums) {
        free(cc.child_paddrs); free(cc.child_kinds); free(cc.child_csums);
        free(buf);
        return STM_ENOMEM;
    }

    s = stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                     NULL, child_record_cb, &cc);
    if (s == STM_OK && cc.err != STM_OK) s = cc.err;
    free(buf);
    if (s != STM_OK) {
        free(cc.child_paddrs); free(cc.child_kinds); free(cc.child_csums);
        return s;
    }

    /* Read each child and deserialize as a leaf. A single insert_ctx
     * threads across all leaves so the sort-order check (R7c P2-6)
     * catches out-of-order keys straddling two leaves as well as
     * in-leaf duplicates.
     *
     * Each child is verified (Merkle) + decrypted (AEAD) under the
     * SAME `gen` that was threaded into this call — the serialize
     * path stamps every node in the tree with the commit's gen. */
    uint8_t *leafbuf = malloc(STM_BTNODE_SIZE);
    if (!leafbuf) {
        free(cc.child_paddrs); free(cc.child_kinds); free(cc.child_csums);
        return STM_ENOMEM;
    }
    insert_ctx ic = { .tree = t };
    for (uint32_t i = 0; i < cc.n_children; i++) {
        if (cc.child_kinds[i] != STM_BPTR_KIND_LEAF) {
            s = STM_ENOTSUPPORTED;
            break;
        }
        s = vt->read(vt_ctx, cc.child_paddrs[i], leafbuf, STM_BTNODE_SIZE);
        if (s != STM_OK) break;
        /* Merkle check: each child's bp_csum (over ciphertext) must
         * match the parent internal node's recorded bp_csum. */
        s = check_merkle_link(leafbuf, &cc.child_csums[i * 32]);
        if (s != STM_OK) break;
        /* AEAD decrypt each leaf under the child's paddr + shared gen. */
        s = stm_btree_node_decrypt(cx, cc.child_paddrs[i], gen, leafbuf);
        if (s != STM_OK) break;
        restore_plaintext_self_csum(leafbuf);
        s = deserialize_leaf(t, leafbuf, &ic);
        if (s != STM_OK) break;
    }

    free(leafbuf);
    free(ic.prev_key);
    free(cc.child_csums);
    free(cc.child_paddrs);
    free(cc.child_kinds);
    return s;
}

/* ========================================================================= */
/* Public: free_tree (reclaim previous snapshot's nodes).                     */
/* ========================================================================= */

stm_status stm_btree_store_free_tree(uint64_t root_paddr, uint64_t root_gen,
                                       uint64_t free_gen,
                                       const stm_btree_store_vtable *vt,
                                       void *vt_ctx,
                                       const stm_btree_crypt_ctx *cx)
{
    if (!vt) return STM_EINVAL;
    if (!vt->read || !vt->free) return STM_EINVAL;
    /* P4-3b: must decrypt internal nodes to enumerate their children. */
    if (!cx || !cx->metadata_key) return STM_EINVAL;

    uint8_t *buf = malloc(STM_BTNODE_SIZE);
    if (!buf) return STM_ENOMEM;

    stm_status s = vt->read(vt_ctx, root_paddr, buf, STM_BTNODE_SIZE);
    if (s != STM_OK) { free(buf); return s; }

    /* P4-3b: decrypt before stm_btnode_peek. On a tampered or
     * wrong-gen node, AEAD decrypt returns STM_EBADTAG and we abort
     * without enumerating children; those bytes on disk remain
     * allocated and will leak (bounded by the tampered subtree)
     * rather than being freed silently under corrupt data. */
    s = stm_btree_node_decrypt(cx, root_paddr, root_gen, buf);
    if (s != STM_OK) { free(buf); return s; }
    restore_plaintext_self_csum(buf);

    stm_btnode_info info;
    s = stm_btnode_peek(buf, STM_BTNODE_SIZE, &info);
    if (s != STM_OK) { free(buf); return s; }

    if (info.kind == STM_BTNODE_KIND_LEAF) {
        free(buf);
        return vt->free(vt_ctx, root_paddr, free_gen);
    }

    /* INTERNAL root. Enumerate children; free each (must be LEAF per
     * the two-level invariant); then free the internal itself.
     *
     * R8-P0-1: `child_record_cb` unconditionally writes 32 bytes into
     * `cc.child_csums` per enumeration. The previous revision didn't
     * allocate this buffer on the free_tree path (only on the
     * deserialize path), causing a deterministic segfault on the
     * first multi-leaf commit cycle after P4-1 landed. We don't
     * actually USE the csums here — free_tree only needs paddrs —
     * but allocating the buffer symmetrically is the cheap fix and
     * keeps the callback usable everywhere. */
    uint32_t cap = info.n_entries + 1u;
    child_collect cc = { 0 };
    cc.child_paddrs = calloc(cap, sizeof *cc.child_paddrs);
    cc.child_kinds  = calloc(cap, sizeof *cc.child_kinds);
    cc.child_csums  = calloc((size_t)cap * 32u, sizeof *cc.child_csums);
    cc.cap          = cap;
    if (!cc.child_paddrs || !cc.child_kinds || !cc.child_csums) {
        free(cc.child_paddrs); free(cc.child_kinds); free(cc.child_csums);
        free(buf);
        return STM_ENOMEM;
    }

    s = stm_btnode_internal_decode(buf, STM_BTNODE_SIZE, NULL,
                                     NULL, child_record_cb, &cc);
    if (s == STM_OK && cc.err != STM_OK) s = cc.err;
    free(buf);
    if (s != STM_OK) {
        free(cc.child_paddrs); free(cc.child_kinds); free(cc.child_csums);
        return s;
    }

    for (uint32_t i = 0; i < cc.n_children; i++) {
        if (cc.child_kinds[i] != STM_BPTR_KIND_LEAF) {
            s = STM_ENOTSUPPORTED;
            break;
        }
        s = vt->free(vt_ctx, cc.child_paddrs[i], free_gen);
        if (s != STM_OK) break;
    }
    free(cc.child_paddrs);
    free(cc.child_kinds);
    free(cc.child_csums);
    if (s != STM_OK) return s;

    return vt->free(vt_ctx, root_paddr, free_gen);
}
