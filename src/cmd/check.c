/*
 * stratum check — filesystem diagnostic / forensic tool.
 *
 * Goes far beyond "does it mount": reads both superblocks side by side,
 * probes each block pointer with detailed failure reporting (read /
 * checksum / decrypt / decompress / decode), reports topology per tree
 * level, enumerates snapshots independently and walks each snapshot's
 * tree, and reconciles allocator refcounts against tree-reachability.
 *
 * Designed to be useful when things are already broken — every phase
 * runs independently so a corrupt main tree doesn't hide problems in
 * the snapshot tree or vice versa.
 */

#include "stratum/types.h"
#include "stratum/block.h"
#include "stratum/super.h"
#include "stratum/btree.h"
#include "stratum/bptr.h"
#include "stratum/key.h"
#include "stratum/inode.h"
#include "stratum/snap.h"
#include "stratum/snapshot.h"
#include "stratum/crypto.h"
#include "stratum/alloc.h"
#include "stratum/fs.h"
#include "stratum/compress.h"
#include "stratum/csum.h"
#include "../btree/btree_internal.h"
#include "../fs/fs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define MAX_TREE_DEPTH 32

/* ── helpers ─────────────────────────────────────────────────────────── */

static const char *human_size_buf(uint64_t bytes)
{
    static char buf[32];
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double val = (double)bytes;
    int u = 0;
    while (val >= 1024.0 && u < 4) { val /= 1024.0; u++; }
    snprintf(buf, sizeof(buf), "%.1f %s", val, units[u]);
    return buf;
}

static const char *comp_name(uint8_t c)
{
    switch (c) {
        case STM_COMP_NONE: return "none";
        case STM_COMP_LZ4:  return "lz4";
        case STM_COMP_ZSTD: return "zstd";
        default:            return "?";
    }
}

static const char *enc_name(uint8_t a)
{
    switch (a) {
        case 0:  return "none";
        case 1:  return "XChaCha20-Poly1305";
        case 2:  return "ML-KEM + XChaCha20";
        default: return "?";
    }
}

#include "cli_common.h"
#define read_pass_stdin_local() stm_cli_read_pass_stdin()

/* Print a hex digest. */
static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* Print first N bytes of a bptr csum. */
static void print_csum(const uint8_t *csum)
{
    int all_zero = 1;
    for (int i = 0; i < STM_BLAKE3_LEN; i++) if (csum[i]) { all_zero = 0; break; }
    if (all_zero) { printf("(zero)"); return; }
    print_hex(csum, 8);
    printf("...");
}

/* ── block-level probe ────────────────────────────────────────────────── */
/*
 * Reproduces the btree read pipeline step by step so we can report
 * exactly where it breaks:
 *
 *   paddr+csize bounds → read → verify csum → (decrypt) → (decompress) → decode
 *
 * On success, *out_node is the decoded node (caller must stm_node_free).
 * On failure, status tells us where we stopped.
 */
enum probe_status {
    PROBE_OK = 0,
    PROBE_BOUNDS,
    PROBE_READ_FAIL,
    PROBE_CSUM_FAIL,
    PROBE_DECRYPT_FAIL,
    PROBE_DECOMPRESS_FAIL,
    PROBE_DECODE_FAIL,
};

static const char *probe_status_name(enum probe_status s)
{
    switch (s) {
        case PROBE_OK:              return "ok";
        case PROBE_BOUNDS:          return "past device end";
        case PROBE_READ_FAIL:       return "read failed";
        case PROBE_CSUM_FAIL:       return "checksum mismatch";
        case PROBE_DECRYPT_FAIL:    return "decrypt failed (AEAD tag)";
        case PROBE_DECOMPRESS_FAIL: return "decompress failed";
        case PROBE_DECODE_FAIL:     return "node decode failed";
    }
    return "?";
}

static enum probe_status probe_bptr(struct stm_block_dev *dev,
                                    struct stm_crypto *crypto,
                                    uint32_t tree_id,
                                    uint64_t dev_blocks,
                                    const struct stm_bptr *bptr,
                                    struct stm_node **out_node)
{
    uint64_t paddr = le64_to_cpu(bptr->bp_paddr);
    uint32_t csize = le32_to_cpu(bptr->bp_csize);
    uint32_t lsize = le32_to_cpu(bptr->bp_lsize);
    uint8_t  comp  = bptr->bp_comp;

    uint64_t block = paddr / STM_BLOCK_SIZE;
    uint32_t nblk  = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    if (block + nblk > dev_blocks) return PROBE_BOUNDS;
    if (csize == 0) return PROBE_BOUNDS;

    uint8_t *raw = malloc(csize);
    if (!raw) return PROBE_READ_FAIL;
    if (stm_block_read(dev, paddr, raw, csize) != 0) {
        free(raw);
        return PROBE_READ_FAIL;
    }

    if (stm_csum_verify(raw, csize, bptr->bp_csum) != 0) {
        free(raw);
        return PROBE_CSUM_FAIL;
    }

    uint32_t data_len = csize;
    uint8_t *plain = raw;

    if (crypto) {
        uint8_t *dec = malloc(csize);
        if (!dec) { free(raw); return PROBE_READ_FAIL; }
        uint32_t plen = 0;
        uint64_t write_gen = le64_to_cpu(bptr->bp_write_gen);
        struct stm_ad_node ad = {
            .ad_magic    = cpu_to_le32(STM_AD_MAGIC_NODE),
            .ad_version  = cpu_to_le32(1),
            .ad_tree_id  = cpu_to_le32(tree_id),
            .ad_reserved = cpu_to_le32(0),
        };
        int rc = stm_crypto_decrypt(crypto, paddr, write_gen,
                                    &ad, sizeof(ad),
                                    raw, csize, dec, &plen);
        free(raw);
        if (rc != 0) { free(dec); return PROBE_DECRYPT_FAIL; }
        plain = dec;
        data_len = plen;
    }

    uint8_t *decoded_bytes = plain;
    uint32_t decoded_len   = data_len;

    if (comp != STM_COMP_NONE) {
        uint8_t *dc = calloc(1, lsize);
        if (!dc) { free(plain); return PROBE_READ_FAIL; }
        int rc = stm_decompress(comp, plain, data_len, dc, lsize);
        free(plain);
        if (rc != 0) { free(dc); return PROBE_DECOMPRESS_FAIL; }
        decoded_bytes = dc;
        decoded_len   = lsize;
    }

    struct stm_node *n = NULL;
    int rc = stm_node_decode(decoded_bytes, decoded_len, &n);
    free(decoded_bytes);
    if (rc != 0) return PROBE_DECODE_FAIL;
    if (out_node) *out_node = n;
    else          stm_node_free(n);
    return PROBE_OK;
}

/* ── walk context ─────────────────────────────────────────────────────── */

struct walk_ctx {
    struct stm_block_dev *dev;
    struct stm_crypto    *crypto;
    uint64_t dev_blocks;
    /* topology */
    uint64_t nodes_at_level[MAX_TREE_DEPTH];
    uint64_t bytes_at_level[MAX_TREE_DEPTH];
    uint16_t max_level_seen;
    uint64_t total_nodes;
    uint64_t total_node_bytes;
    /* leaf stats */
    uint64_t leaf_entries;
    uint64_t inode_count;
    uint64_t extent_count;
    uint64_t extent_bytes_logical;
    uint64_t extent_bytes_disk;
    /* refcount reconciliation: expected refcount per block */
    uint32_t *refmap;       /* size dev_blocks */
    /* error tallies */
    int errors;
    int warnings;
    /* verbosity */
    int verbose;
    /* filename for reporting */
    const char *tree_label;
    /* AEAD AD context — matches the encrypting tree's stm_btree_set_id. */
    uint32_t tree_id;
};

static void ref_add(struct walk_ctx *w, uint64_t block, uint32_t count)
{
    if (!w->refmap) return;
    for (uint32_t i = 0; i < count && block + i < w->dev_blocks; i++)
        w->refmap[block + i]++;
}

/* ── manual tree walker ──────────────────────────────────────────────── */

static void walk_node_rec(struct walk_ctx *w,
                          const struct stm_bptr *bptr,
                          uint16_t expected_level);

static void report_probe_failure(struct walk_ctx *w,
                                 const struct stm_bptr *bptr,
                                 enum probe_status st,
                                 uint16_t level)
{
    w->errors++;
    uint64_t paddr = le64_to_cpu(bptr->bp_paddr);
    uint32_t csize = le32_to_cpu(bptr->bp_csize);
    uint32_t lsize = le32_to_cpu(bptr->bp_lsize);
    printf("  ERROR [%s] node at paddr=0x%llx (block %llu) level=%u: %s\n",
           w->tree_label,
           (unsigned long long)paddr,
           (unsigned long long)(paddr / STM_BLOCK_SIZE),
           level, probe_status_name(st));
    printf("           csize=%u lsize=%u comp=%s csum=",
           csize, lsize, comp_name(bptr->bp_comp));
    print_csum(bptr->bp_csum);
    printf("\n");
}

static void walk_entry(struct walk_ctx *w,
                       const struct stm_key *key,
                       const void *val, uint32_t vlen)
{
    w->leaf_entries++;
    struct stm_key_cpu kc = stm_key_to_cpu(key);

    if (kc.type == STM_KEY_INODE) {
        w->inode_count++;
        if (vlen != sizeof(struct stm_inode)) {
            printf("  ERROR [%s] inode %llu: value size %u (expected %zu)\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   vlen, sizeof(struct stm_inode));
            w->errors++;
        }
    } else if (kc.type == STM_KEY_DATA) {
        w->extent_count++;
        if (vlen != sizeof(struct stm_extent)) {
            printf("  ERROR [%s] ino %llu offset %llu: extent vsize %u\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   (unsigned long long)kc.offset, vlen);
            w->errors++;
            return;
        }
        struct stm_extent ext;
        memcpy(&ext, val, sizeof(ext));
        uint64_t ep    = le64_to_cpu(ext.se_paddr);
        uint32_t dlen  = le32_to_cpu(ext.se_dlen);
        uint32_t clen  = stm_extent_clen(&ext);
        uint8_t  comp  = stm_extent_comp(&ext);
        w->extent_bytes_logical += dlen;

        uint32_t disk_len = w->crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
        w->extent_bytes_disk += disk_len;
        uint64_t block = ep / STM_BLOCK_SIZE;
        uint32_t nblk  = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;

        if (ep == 0) {
            printf("  ERROR [%s] ino %llu offset %llu: extent paddr is 0 (SB)\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   (unsigned long long)kc.offset);
            w->errors++;
        }
        if (block + nblk > w->dev_blocks) {
            printf("  ERROR [%s] ino %llu offset %llu: extent past device end\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   (unsigned long long)kc.offset);
            w->errors++;
        }
        if (dlen > STM_EXTENT_SIZE) {
            printf("  ERROR [%s] ino %llu offset %llu: dlen %u > max %u\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   (unsigned long long)kc.offset, dlen, STM_EXTENT_SIZE);
            w->errors++;
        }
        if (comp == STM_COMP_NONE && clen != dlen) {
            printf("  ERROR [%s] ino %llu offset %llu: comp=NONE clen=%u != dlen=%u\n",
                   w->tree_label, (unsigned long long)kc.ino,
                   (unsigned long long)kc.offset, clen, dlen);
            w->errors++;
        }

        ref_add(w, block, nblk);
    }
}

static void walk_node_rec(struct walk_ctx *w,
                          const struct stm_bptr *bptr,
                          uint16_t expected_level)
{
    if (stm_bptr_is_null(bptr)) return;

    struct stm_node *n = NULL;
    enum probe_status st = probe_bptr(w->dev, w->crypto, w->tree_id,
                                      w->dev_blocks, bptr, &n);
    if (st != PROBE_OK) {
        report_probe_failure(w, bptr, st, expected_level);
        return;
    }

    /* Account for this node's block(s). */
    uint64_t paddr = le64_to_cpu(bptr->bp_paddr);
    uint32_t csize = le32_to_cpu(bptr->bp_csize);
    uint32_t nblk  = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    ref_add(w, paddr / STM_BLOCK_SIZE, nblk);
    w->total_nodes++;
    w->total_node_bytes += csize;

    uint16_t lvl = n->level;
    if (lvl < MAX_TREE_DEPTH) {
        w->nodes_at_level[lvl]++;
        w->bytes_at_level[lvl] += csize;
        if (lvl > w->max_level_seen) w->max_level_seen = lvl;
    }
    /* Stored tree_height in the superblock vs in-node level is not a
     * strict invariant (height is a +1-biased descendant count), so we
     * don't flag mismatches here. We only use `expected_level` to know
     * whether to descend into children. */
    (void)expected_level;

    if (lvl == 0) {
        /* Leaf: walk entries. */
        for (uint32_t i = 0; i < n->nentries; i++) {
            const struct stm_leaf_entry *e = &n->entries[i];
            walk_entry(w, &e->key, e->val, e->vlen);
        }
    } else {
        /* Internal: recurse into children, also walk message buffer. */
        for (uint32_t i = 0; i < n->nmsgs; i++) {
            const struct stm_msg_entry *m = &n->msgs[i];
            /* Messages carry inserted values mid-flight; count like leaf entries. */
            walk_entry(w, &m->key, m->val, m->vlen);
        }
        for (uint32_t i = 0; i < n->nkeys + 1; i++) {
            walk_node_rec(w, &n->children[i], lvl - 1);
        }
    }
    stm_node_free(n);
}

/* ── superblock side-by-side ─────────────────────────────────────────── */

static int sb_valid(const struct stm_superblock *sb)
{
    return le64_to_cpu(sb->ss_magic) == STM_MAGIC;
}

static int sb_csum_ok(const struct stm_superblock *sb)
{
    struct stm_superblock tmp = *sb;
    memset(tmp.ss_csum, 0, sizeof(tmp.ss_csum));
    return stm_csum_verify(&tmp, sizeof(tmp), sb->ss_csum) == 0;
}

static void print_sb_side(const struct stm_superblock *sa,
                          const struct stm_superblock *sb)
{
    int a_ok = sb_valid(sa);
    int b_ok = sb_valid(sb);
    int a_cs = a_ok && sb_csum_ok(sa);
    int b_cs = b_ok && sb_csum_ok(sb);

    printf("%-25s  %-20s  %-20s\n", "", "Superblock A", "Superblock B");
    printf("%-25s  %-20s  %-20s\n", "-------------------------", "--------------------", "--------------------");
    printf("%-25s  %-20s  %-20s\n",
           "magic",
           a_ok ? "valid" : "INVALID",
           b_ok ? "valid" : "INVALID");
    printf("%-25s  %-20s  %-20s\n",
           "checksum",
           a_ok ? (a_cs ? "valid" : "MISMATCH") : "-",
           b_ok ? (b_cs ? "valid" : "MISMATCH") : "-");
    if (a_ok || b_ok) {
        char ag[32] = "-", bg[32] = "-";
        if (a_ok) snprintf(ag, sizeof(ag), "%llu", (unsigned long long)le64_to_cpu(sa->ss_gen));
        if (b_ok) snprintf(bg, sizeof(bg), "%llu", (unsigned long long)le64_to_cpu(sb->ss_gen));
        printf("%-25s  %-20s  %-20s\n", "generation", ag, bg);

        char av[32] = "-", bv[32] = "-";
        if (a_ok) snprintf(av, sizeof(av), "%u", le32_to_cpu(sa->ss_version));
        if (b_ok) snprintf(bv, sizeof(bv), "%u", le32_to_cpu(sb->ss_version));
        printf("%-25s  %-20s  %-20s\n", "version", av, bv);

        char ar[32] = "-", br[32] = "-";
        if (a_ok) snprintf(ar, sizeof(ar), "0x%llx",
                           (unsigned long long)le64_to_cpu(sa->ss_root.bp_paddr));
        if (b_ok) snprintf(br, sizeof(br), "0x%llx",
                           (unsigned long long)le64_to_cpu(sb->ss_root.bp_paddr));
        printf("%-25s  %-20s  %-20s\n", "root bptr paddr", ar, br);

        char ah[32] = "-", bh[32] = "-";
        if (a_ok) snprintf(ah, sizeof(ah), "%u", le16_to_cpu(sa->ss_tree_height));
        if (b_ok) snprintf(bh, sizeof(bh), "%u", le16_to_cpu(sb->ss_tree_height));
        printf("%-25s  %-20s  %-20s\n", "tree height", ah, bh);

        char asr[32] = "-", bsr[32] = "-";
        if (a_ok) snprintf(asr, sizeof(asr), "0x%llx",
                           (unsigned long long)le64_to_cpu(sa->ss_snap_root.bp_paddr));
        if (b_ok) snprintf(bsr, sizeof(bsr), "0x%llx",
                           (unsigned long long)le64_to_cpu(sb->ss_snap_root.bp_paddr));
        printf("%-25s  %-20s  %-20s\n", "snap_root bptr paddr", asr, bsr);

        char ash[32] = "-", bsh[32] = "-";
        if (a_ok) snprintf(ash, sizeof(ash), "%u", le16_to_cpu(sa->ss_snap_height));
        if (b_ok) snprintf(bsh, sizeof(bsh), "%u", le16_to_cpu(sb->ss_snap_height));
        printf("%-25s  %-20s  %-20s\n", "snap_tree height", ash, bsh);

        char an[32] = "-", bn[32] = "-";
        if (a_ok) snprintf(an, sizeof(an), "%llu",
                           (unsigned long long)le64_to_cpu(sa->ss_next_ino));
        if (b_ok) snprintf(bn, sizeof(bn), "%llu",
                           (unsigned long long)le64_to_cpu(sb->ss_next_ino));
        printf("%-25s  %-20s  %-20s\n", "next_ino", an, bn);

        char asid[32] = "-", bsid[32] = "-";
        if (a_ok) snprintf(asid, sizeof(asid), "%llu",
                           (unsigned long long)le64_to_cpu(sa->ss_next_snap_id));
        if (b_ok) snprintf(bsid, sizeof(bsid), "%llu",
                           (unsigned long long)le64_to_cpu(sb->ss_next_snap_id));
        printf("%-25s  %-20s  %-20s\n", "next_snap_id", asid, bsid);

        char aa[32] = "-", ba[32] = "-";
        if (a_ok) snprintf(aa, sizeof(aa), "%llu",
                           (unsigned long long)le64_to_cpu(sa->ss_alloc_next));
        if (b_ok) snprintf(ba, sizeof(ba), "%llu",
                           (unsigned long long)le64_to_cpu(sb->ss_alloc_next));
        printf("%-25s  %-20s  %-20s\n", "alloc_next", aa, ba);

        char ab[32] = "-", bb[32] = "-";
        if (a_ok) snprintf(ab, sizeof(ab), "%u", sa->ss_enc_algo);
        if (b_ok) snprintf(bb, sizeof(bb), "%u", sb->ss_enc_algo);
        printf("%-25s  %-20s  %-20s\n", "enc_algo", ab, bb);

        char ac[32] = "-", bc[32] = "-";
        if (a_ok) snprintf(ac, sizeof(ac), "%s", comp_name(sa->ss_comp_algo));
        if (b_ok) snprintf(bc, sizeof(bc), "%s", comp_name(sb->ss_comp_algo));
        printf("%-25s  %-20s  %-20s\n", "comp_algo", ac, bc);
    }
    printf("\n");
}

/* ── snapshot enumeration ─────────────────────────────────────────────── */

struct snap_scan_ctx {
    struct walk_ctx *w;
    int count;
};

static int snap_scan_cb(const struct stm_key *key, const void *val,
                        uint32_t vlen, void *ctx)
{
    struct snap_scan_ctx *s = ctx;
    (void)key;
    if (vlen < sizeof(struct stm_snapshot) + 1) return 0;

    struct stm_snapshot snap;
    memcpy(&snap, val, sizeof(snap));
    uint8_t nlen = ((const uint8_t *)val)[sizeof(snap)];
    if (nlen > 63) nlen = 63;
    char name[64] = {0};
    memcpy(name, (const uint8_t *)val + sizeof(snap) + 1, nlen);

    s->count++;
    printf("  #%-4llu gen=%-8llu refcount=%u height=%u root_paddr=0x%llx name=%s\n",
           (unsigned long long)le64_to_cpu(snap.ssp_id),
           (unsigned long long)le64_to_cpu(snap.ssp_gen),
           le32_to_cpu(snap.ssp_refcount),
           le16_to_cpu(snap.ssp_tree_height),
           (unsigned long long)le64_to_cpu(snap.ssp_root.bp_paddr),
           name);

    /* Walk this snapshot's tree for additional diagnostics. Snapshot
     * subtrees are frozen main-tree roots — their nodes were written
     * with tree_id = MAIN, so swap the AEAD AD context before descent
     * and restore after. */
    char lbl[64];
    snprintf(lbl, sizeof(lbl), "snap#%llu",
             (unsigned long long)le64_to_cpu(snap.ssp_id));
    const char *old_label = s->w->tree_label;
    uint32_t old_tree_id  = s->w->tree_id;
    s->w->tree_label = lbl;
    s->w->tree_id    = STM_TREE_ID_MAIN;
    walk_node_rec(s->w, &snap.ssp_root, le16_to_cpu(snap.ssp_tree_height));
    s->w->tree_label = old_label;
    s->w->tree_id    = old_tree_id;
    return 0;
}

/* ── refcount reconciliation ─────────────────────────────────────────── */

static void reconcile(struct walk_ctx *w, struct stm_alloc *alloc)
{
    if (!w->refmap || !alloc) return;
    /* The allocator holds refcounts set by mount-time mark (stm_alloc_mark).
     * Our refmap accumulates one +1 per on-disk reference we saw while
     * walking every tree. They should match (modulo REFCOUNT_PENDING and
     * the 2 superblock blocks which we don't count). */

    uint64_t expected_leaks = 0;   /* we saw it, alloc says free */
    uint64_t over_counts = 0;      /* alloc says in-use but we saw fewer refs */
    uint64_t under_counts = 0;     /* we saw more refs than alloc says */

    /* Scan all blocks except the two superblock slots. */
    for (uint64_t b = 2; b < w->dev_blocks; b++) {
        uint32_t expected = w->refmap[b];
        uint32_t actual = stm_alloc_get_refcount(alloc, b);

        if (actual == 0xFFFFFFFFu) continue; /* REFCOUNT_PENDING: transient */
        if (expected == 0 && actual != 0) over_counts++;
        else if (expected != 0 && actual == 0) expected_leaks++;
        else if (expected != actual) under_counts++;
    }

    if (expected_leaks + over_counts + under_counts == 0) {
        printf("  Allocator refcounts: consistent with tree walk.\n");
        return;
    }
    w->warnings++;
    printf("  WARN: allocator refcount reconciliation:\n");
    printf("    live-refs we saw but allocator says free:  %llu blocks\n",
           (unsigned long long)expected_leaks);
    printf("    allocator claims in-use but we saw no refs: %llu blocks\n",
           (unsigned long long)over_counts);
    printf("    refcount mismatch (live-refs != allocator): %llu blocks\n",
           (unsigned long long)under_counts);

    if (w->verbose) {
        int shown = 0;
        for (uint64_t b = 2; b < w->dev_blocks && shown < 40; b++) {
            uint32_t expected = w->refmap[b];
            uint32_t actual = stm_alloc_get_refcount(alloc, b);
            if (actual == 0xFFFFFFFFu) continue;
            if (expected != actual) {
                printf("      block %llu: expected %u, allocator=%u\n",
                       (unsigned long long)b, expected, actual);
                shown++;
            }
        }
        if (shown == 40) printf("      ... (more; truncated)\n");
    }
}

/* ── semantic checks ─────────────────────────────────────────────────── */

/* Walk the main tree's leaves, tracking inodes and their dirent references. */

struct sem_ctx {
    /* Hash of inode numbers observed. Simple linear array for now. */
    uint64_t *inodes;
    size_t    inode_cap, inode_count;
    /* Dirents: (parent_ino, child_ino) references. */
    uint64_t *dirent_ptrs;   /* child_ino */
    size_t    dp_cap, dp_count;
    /* Tallies */
    int errors;
    int warnings;
};

static void sem_add_inode(struct sem_ctx *s, uint64_t ino)
{
    if (s->inode_count == s->inode_cap) {
        size_t nc = s->inode_cap ? s->inode_cap * 2 : 64;
        uint64_t *np = realloc(s->inodes, nc * sizeof(*np));
        if (!np) return;
        s->inodes = np;
        s->inode_cap = nc;
    }
    s->inodes[s->inode_count++] = ino;
}

static void sem_add_dirent(struct sem_ctx *s, uint64_t child)
{
    if (s->dp_count == s->dp_cap) {
        size_t nc = s->dp_cap ? s->dp_cap * 2 : 64;
        uint64_t *np = realloc(s->dirent_ptrs, nc * sizeof(*np));
        if (!np) return;
        s->dirent_ptrs = np;
        s->dp_cap = nc;
    }
    s->dirent_ptrs[s->dp_count++] = child;
}

static int sem_scan_cb(const struct stm_key *key, const void *val,
                       uint32_t vlen, void *ctx)
{
    struct sem_ctx *s = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);

    if (kc.type == STM_KEY_INODE) {
        sem_add_inode(s, kc.ino);
    } else if (kc.type == STM_KEY_DIRENT && vlen >= 9) {
        le64 child_le;
        memcpy(&child_le, val, 8);
        sem_add_dirent(s, le64_to_cpu(child_le));
    }
    return 0;
}

static int u64_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y);
}

static int u64_contains(const uint64_t *arr, size_t n, uint64_t needle)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (arr[mid] == needle) return 1;
        if (arr[mid] < needle) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static void run_semantic_checks(struct stm_fs *fs, struct walk_ctx *w)
{
    struct sem_ctx s = {0};
    struct stm_key lo = stm_mk_key(0, 0, 0);
    struct stm_key hi = stm_mk_key(UINT64_MAX, UINT8_MAX, UINT64_MAX);
    stm_btree_scan(fs->tree, &lo, &hi, sem_scan_cb, &s);

    qsort(s.inodes, s.inode_count, sizeof(*s.inodes), u64_cmp);
    qsort(s.dirent_ptrs, s.dp_count, sizeof(*s.dirent_ptrs), u64_cmp);

    /* Broken dirents: dirent points at inode that doesn't exist. */
    size_t broken = 0;
    for (size_t i = 0; i < s.dp_count; i++) {
        if (!u64_contains(s.inodes, s.inode_count, s.dirent_ptrs[i])) {
            broken++;
        }
    }
    /* Orphan inodes: inode that is not the root and has no dirent pointing to it. */
    size_t orphans = 0;
    for (size_t i = 0; i < s.inode_count; i++) {
        uint64_t ino = s.inodes[i];
        if (ino == STM_ROOT_INO) continue;
        if (!u64_contains(s.dirent_ptrs, s.dp_count, ino)) orphans++;
    }

    printf("  Semantic checks:\n");
    printf("    inodes:        %zu\n", s.inode_count);
    printf("    dirent refs:   %zu\n", s.dp_count);
    printf("    broken dirent: %zu\n", broken);
    printf("    orphan inode:  %zu\n", orphans);
    if (broken > 0)  { w->errors++;   }
    if (orphans > 0) { w->warnings++; }
    free(s.inodes);
    free(s.dirent_ptrs);
}

/* ── entrypoint ──────────────────────────────────────────────────────── */

int stm_cmd_check(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL;
    int verbose = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin_local(); continue; }
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) { verbose = 1; continue; }
        if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum check <path> [--pass <p>|--pass-stdin] [--verbose]\n");
        return 1;
    }

    printf("Checking %s\n\n", path);

    /* ── Phase 1: superblocks side-by-side ─────────────────────────── */
    struct stm_block_dev dev;
    int rc = stm_file_backend_open(path, 0, 0, &dev);
    if (rc) { fprintf(stderr, "Cannot open: %s\n", strerror(-rc)); return 1; }

    struct stm_superblock sa, sb;
    stm_block_read(&dev, STM_SB_OFFSET_A, &sa, sizeof(sa));
    stm_block_read(&dev, STM_SB_OFFSET_B, &sb, sizeof(sb));

    uint64_t dev_bytes = 0;
    stm_block_size(&dev, &dev_bytes);
    uint64_t dev_blocks = dev_bytes / STM_BLOCK_SIZE;
    printf("Device size: %s (%llu blocks)\n\n",
           human_size_buf(dev_bytes), (unsigned long long)dev_blocks);

    print_sb_side(&sa, &sb);

    int a_ok = sb_valid(&sa), b_ok = sb_valid(&sb);
    struct stm_superblock *chosen = NULL;
    if (a_ok && b_ok) {
        chosen = (le64_to_cpu(sa.ss_gen) >= le64_to_cpu(sb.ss_gen)) ? &sa : &sb;
        printf("Using: %s (higher gen)\n\n", chosen == &sa ? "A" : "B");
    } else if (a_ok || b_ok) {
        chosen = a_ok ? &sa : &sb;
        printf("Using: %s (only valid)\n\n", a_ok ? "A" : "B");
    } else {
        printf("FATAL: no valid superblock.\n");
        stm_block_close(&dev);
        return 1;
    }

    /* ── Phase 2: open filesystem (needed for fs->tree / fs->snap_tree) */
    stm_block_close(&dev);
    struct stm_fs *fs = NULL;
    printf("Opening filesystem...\n");
    /* Use the read-only open path. `check` is a diagnostic tool and must
     * not modify the volume — in particular, it must NOT trigger the
     * encrypted-mount gen bump that stm_fs_open performs. Users running
     * `check` on a degraded volume (bad sector at an SB slot) need a path
     * that doesn't require writes to succeed. */
    rc = stm_fs_open_ro(path, pass, &fs);
    if (rc) {
        fprintf(stderr, "FATAL: cannot open: %s\n", strerror(-rc));
        return 1;
    }

    /* Shared context for every walk. refmap sized over the whole device. */
    struct walk_ctx ctx = {
        .dev         = &fs->dev,
        .crypto      = stm_btree_get_crypto(fs->tree),
        .dev_blocks  = dev_blocks,
        .refmap      = calloc(dev_blocks, sizeof(uint32_t)),
        .verbose     = verbose,
    };

    /* ── Phase 3: walk main tree ───────────────────────────────────── */
    printf("\n── Main tree ─────────────────────────────────────\n");
    ctx.tree_label = "main";
    ctx.tree_id    = STM_TREE_ID_MAIN;
    struct stm_bptr main_root = stm_btree_root(fs->tree);
    if (stm_bptr_is_null(&main_root)) {
        printf("  (main tree root is null — empty or newly created)\n");
    } else {
        walk_node_rec(&ctx, &main_root, stm_btree_height(fs->tree));
    }
    uint64_t main_nodes = ctx.total_nodes;
    uint64_t main_bytes = ctx.total_node_bytes;
    printf("  nodes: %llu (%s)\n",
           (unsigned long long)main_nodes, human_size_buf(main_bytes));
    printf("  leaf entries: %llu (inodes=%llu, extents=%llu, other=%llu)\n",
           (unsigned long long)ctx.leaf_entries,
           (unsigned long long)ctx.inode_count,
           (unsigned long long)ctx.extent_count,
           (unsigned long long)(ctx.leaf_entries - ctx.inode_count - ctx.extent_count));
    printf("  extent data: %s logical, %s on disk\n",
           human_size_buf(ctx.extent_bytes_logical),
           human_size_buf(ctx.extent_bytes_disk));
    if (ctx.max_level_seen > 0) {
        printf("  topology:\n");
        for (int16_t l = (int16_t)ctx.max_level_seen; l >= 0; l--) {
            printf("    level %2d: %llu nodes (%s)\n", l,
                   (unsigned long long)ctx.nodes_at_level[l],
                   human_size_buf(ctx.bytes_at_level[l]));
        }
    }

    /* Reset per-tree stats before walking snap tree, keep refmap global. */
    uint64_t saved_err = ctx.errors, saved_warn = ctx.warnings;
    memset(ctx.nodes_at_level, 0, sizeof(ctx.nodes_at_level));
    memset(ctx.bytes_at_level, 0, sizeof(ctx.bytes_at_level));
    ctx.total_nodes = 0; ctx.total_node_bytes = 0; ctx.max_level_seen = 0;
    ctx.leaf_entries = 0; ctx.inode_count = 0; ctx.extent_count = 0;
    ctx.extent_bytes_logical = 0; ctx.extent_bytes_disk = 0;

    /* ── Phase 4: walk snap tree + enumerate snapshots ─────────────── */
    printf("\n── Snapshot tree ─────────────────────────────────\n");
    if (!fs->snap_tree) {
        printf("  (no snapshot tree)\n");
    } else {
        ctx.tree_label = "snap_tree";
        ctx.tree_id    = STM_TREE_ID_SNAP;
        struct stm_bptr snap_root = stm_btree_root(fs->snap_tree);
        walk_node_rec(&ctx, &snap_root, stm_btree_height(fs->snap_tree));
        printf("  nodes: %llu (%s)\n",
               (unsigned long long)ctx.total_nodes, human_size_buf(ctx.total_node_bytes));

        printf("\n  Snapshots:\n");
        struct snap_scan_ctx s = { .w = &ctx, .count = 0 };
        struct stm_key lo = stm_mk_key(0, STM_KEY_SNAP, 0);
        struct stm_key hi = stm_mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
        stm_btree_scan(fs->snap_tree, &lo, &hi, snap_scan_cb, &s);
        if (s.count == 0) printf("    (none)\n");
    }

    /* ── Phase 5: semantic checks on main tree ─────────────────────── */
    printf("\n── Semantic checks ───────────────────────────────\n");
    run_semantic_checks(fs, &ctx);

    /* ── Phase 6: refcount reconciliation ──────────────────────────── */
    printf("\n── Allocator reconciliation ──────────────────────\n");
    printf("  free blocks: %llu / %llu\n",
           (unsigned long long)stm_alloc_free_count(fs->alloc),
           (unsigned long long)dev_blocks);
    reconcile(&ctx, fs->alloc);

    /* ── Summary ───────────────────────────────────────────────────── */
    (void)saved_err; (void)saved_warn;  /* kept for future per-phase tallying */
    printf("\n── Summary ──────────────────────────────────────\n");
    if (ctx.errors == 0 && ctx.warnings == 0) {
        printf("Filesystem is clean.\n");
    } else {
        printf("%d error(s), %d warning(s).\n", ctx.errors, ctx.warnings);
    }

    free(ctx.refmap);
    stm_fs_close(fs);
    return ctx.errors > 0 ? 1 : 0;
}
