#include "test_main.h"
#include "btree/btree_internal.h"

/* ── leaf basics ────────────────────────────────────────────────────── */

STM_TEST(test_leaf_insert_find)
{
    struct stm_node *leaf = stm_node_alloc_leaf(1);
    STM_ASSERT(leaf != NULL);

    struct stm_key_cpu kc = { .ino = 10, .type = STM_KEY_DATA, .offset = 0 };
    struct stm_key k = stm_key_from_cpu(&kc);
    uint8_t val[] = "hello";
    int rc = stm_leaf_insert(leaf, &k, val, 5);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(leaf->nentries, 1u);

    uint32_t idx;
    rc = stm_leaf_find(leaf, &k, &idx);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(idx, 0u);
    STM_ASSERT_EQ(leaf->entries[idx].vlen, 5u);
    STM_ASSERT_MEM_EQ(leaf->entries[idx].val, val, 5);

    stm_node_free(leaf);
}

STM_TEST(test_leaf_insert_sorted)
{
    struct stm_node *leaf = stm_node_alloc_leaf(1);
    uint32_t i;

    /* insert keys in reverse order */
    for (i = 10; i > 0; i--) {
        struct stm_key_cpu kc = { .ino = i, .type = STM_KEY_INODE, .offset = 0 };
        struct stm_key k = stm_key_from_cpu(&kc);
        int rc = stm_leaf_insert(leaf, &k, &i, sizeof(i));
        STM_ASSERT_EQ(rc, 0);
    }

    /* verify sorted order */
    for (i = 0; i < leaf->nentries - 1; i++) {
        STM_ASSERT(stm_key_cmp(&leaf->entries[i].key,
                                &leaf->entries[i + 1].key) < 0);
    }
    STM_ASSERT_EQ(leaf->nentries, 10u);

    stm_node_free(leaf);
}

STM_TEST(test_leaf_update)
{
    struct stm_node *leaf = stm_node_alloc_leaf(1);
    struct stm_key_cpu kc = { .ino = 1, .type = STM_KEY_INODE, .offset = 0 };
    struct stm_key k = stm_key_from_cpu(&kc);

    uint32_t v1 = 100;
    stm_leaf_insert(leaf, &k, &v1, sizeof(v1));
    STM_ASSERT_EQ(leaf->nentries, 1u);

    uint32_t v2 = 200;
    stm_leaf_insert(leaf, &k, &v2, sizeof(v2));
    STM_ASSERT_EQ(leaf->nentries, 1u);  /* no duplicate */

    uint32_t idx;
    stm_leaf_find(leaf, &k, &idx);
    uint32_t got;
    memcpy(&got, leaf->entries[idx].val, sizeof(got));
    STM_ASSERT_EQ(got, 200u);

    stm_node_free(leaf);
}

STM_TEST(test_leaf_delete)
{
    struct stm_node *leaf = stm_node_alloc_leaf(1);
    struct stm_key_cpu kc1 = { .ino = 1, .type = STM_KEY_INODE, .offset = 0 };
    struct stm_key_cpu kc2 = { .ino = 2, .type = STM_KEY_INODE, .offset = 0 };
    struct stm_key k1 = stm_key_from_cpu(&kc1);
    struct stm_key k2 = stm_key_from_cpu(&kc2);
    uint8_t v = 42;

    stm_leaf_insert(leaf, &k1, &v, 1);
    stm_leaf_insert(leaf, &k2, &v, 1);
    STM_ASSERT_EQ(leaf->nentries, 2u);

    int rc = stm_leaf_delete(leaf, &k1);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(leaf->nentries, 1u);

    uint32_t idx;
    STM_ASSERT_EQ(stm_leaf_find(leaf, &k1, &idx), -ENOENT);
    STM_ASSERT_EQ(stm_leaf_find(leaf, &k2, &idx), 0);

    stm_node_free(leaf);
}

/* ── encode/decode round-trip ───────────────────────────────────────── */

STM_TEST(test_leaf_encode_decode)
{
    struct stm_node *orig = stm_node_alloc_leaf(42);
    uint32_t i;

    for (i = 0; i < 50; i++) {
        struct stm_key_cpu kc = { .ino = i + 1, .type = STM_KEY_INODE, .offset = 0 };
        struct stm_key k = stm_key_from_cpu(&kc);
        stm_leaf_insert(orig, &k, &i, sizeof(i));
    }

    uint8_t *buf = calloc(1, STM_NODE_SIZE);
    int rc = stm_node_encode(orig, buf, NULL);
    STM_ASSERT_EQ(rc, 0);

    struct stm_node *decoded = NULL;
    rc = stm_node_decode(buf, STM_NODE_SIZE, &decoded);
    STM_ASSERT_EQ(rc, 0);

    STM_ASSERT_EQ(decoded->nentries, orig->nentries);
    STM_ASSERT_EQ(decoded->data_bytes, orig->data_bytes);
    STM_ASSERT_EQ(decoded->gen, orig->gen);
    STM_ASSERT(decoded->flags & STM_NODE_LEAF);

    for (i = 0; i < decoded->nentries; i++) {
        STM_ASSERT_EQ(stm_key_cmp(&decoded->entries[i].key,
                                    &orig->entries[i].key), 0);
        STM_ASSERT_EQ(decoded->entries[i].vlen, orig->entries[i].vlen);
        STM_ASSERT_MEM_EQ(decoded->entries[i].val, orig->entries[i].val,
                          decoded->entries[i].vlen);
    }

    free(buf);
    stm_node_free(orig);
    stm_node_free(decoded);
}

STM_TEST(test_internal_encode_decode)
{
    struct stm_node *n = stm_node_alloc_internal(1, 99);
    struct stm_key_cpu kc = { .ino = 50, .type = STM_KEY_INODE, .offset = 0 };
    struct stm_key pivot = stm_key_from_cpu(&kc);
    struct stm_bptr c0 = stm_bptr_null(), c1 = stm_bptr_null();

    c0.bp_paddr = cpu_to_le64(8192);
    c1.bp_paddr = cpu_to_le64(8192 + STM_NODE_SIZE);
    n->pivots[0]   = pivot;
    n->children[0] = c0;
    n->children[1] = c1;
    n->nkeys = 1;

    /* add a message */
    struct stm_key_cpu mkc = { .ino = 10, .type = STM_KEY_INODE, .offset = 0 };
    struct stm_key mkey = stm_key_from_cpu(&mkc);
    uint32_t mval = 777;
    stm_msg_insert(n, &mkey, STM_MSG_INSERT, 5, &mval, sizeof(mval));
    STM_ASSERT_EQ(n->nmsgs, 1u);

    uint8_t *buf = calloc(1, STM_NODE_SIZE);
    int rc = stm_node_encode(n, buf, NULL);
    STM_ASSERT_EQ(rc, 0);

    struct stm_node *dec = NULL;
    rc = stm_node_decode(buf, STM_NODE_SIZE, &dec);
    STM_ASSERT_EQ(rc, 0);

    STM_ASSERT_EQ(dec->level, 1u);
    STM_ASSERT_EQ(dec->nkeys, 1u);
    STM_ASSERT_EQ(dec->nmsgs, 1u);
    STM_ASSERT_EQ(stm_key_cmp(&dec->pivots[0], &pivot), 0);
    STM_ASSERT_EQ(le64_to_cpu(dec->children[0].bp_paddr), 8192u);
    STM_ASSERT_EQ(dec->msgs[0].op, STM_MSG_INSERT);

    uint32_t got;
    memcpy(&got, dec->msgs[0].val, sizeof(got));
    STM_ASSERT_EQ(got, 777u);

    free(buf);
    stm_node_free(n);
    stm_node_free(dec);
}

/* ── leaf split ─────────────────────────────────────────────────────── */

STM_TEST(test_leaf_split)
{
    struct stm_node *leaf = stm_node_alloc_leaf(1);
    uint32_t i;

    for (i = 0; i < 100; i++) {
        struct stm_key_cpu kc = { .ino = i + 1, .type = STM_KEY_INODE, .offset = 0 };
        struct stm_key k = stm_key_from_cpu(&kc);
        stm_leaf_insert(leaf, &k, &i, sizeof(i));
    }

    struct stm_key split_key;
    struct stm_node *right = NULL;
    int rc = stm_leaf_split(leaf, &split_key, &right);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(right != NULL);

    /* total entries preserved */
    STM_ASSERT_EQ(leaf->nentries + right->nentries, 100u);

    /* left entries < split_key <= right entries */
    for (i = 0; i < leaf->nentries; i++)
        STM_ASSERT(stm_key_cmp(&leaf->entries[i].key, &split_key) < 0);
    for (i = 0; i < right->nentries; i++)
        STM_ASSERT(stm_key_cmp(&right->entries[i].key, &split_key) >= 0);

    stm_node_free(leaf);
    stm_node_free(right);
}

/* ── find_child ─────────────────────────────────────────────────────── */

STM_TEST(test_find_child)
{
    struct stm_node *n = stm_node_alloc_internal(1, 1);
    struct stm_key_cpu kc1 = { .ino = 10, .type = 0, .offset = 0 };
    struct stm_key_cpu kc2 = { .ino = 20, .type = 0, .offset = 0 };
    n->pivots[0] = stm_key_from_cpu(&kc1);
    n->pivots[1] = stm_key_from_cpu(&kc2);
    n->nkeys = 2;

    struct stm_key_cpu q;
    struct stm_key qk;

    q = (struct stm_key_cpu){ .ino = 5, .type = 0, .offset = 0 };
    qk = stm_key_from_cpu(&q);
    STM_ASSERT_EQ(stm_node_find_child(n, &qk), 0u);

    q = (struct stm_key_cpu){ .ino = 10, .type = 0, .offset = 0 };
    qk = stm_key_from_cpu(&q);
    STM_ASSERT_EQ(stm_node_find_child(n, &qk), 1u);

    q = (struct stm_key_cpu){ .ino = 15, .type = 0, .offset = 0 };
    qk = stm_key_from_cpu(&q);
    STM_ASSERT_EQ(stm_node_find_child(n, &qk), 1u);

    q = (struct stm_key_cpu){ .ino = 20, .type = 0, .offset = 0 };
    qk = stm_key_from_cpu(&q);
    STM_ASSERT_EQ(stm_node_find_child(n, &qk), 2u);

    q = (struct stm_key_cpu){ .ino = 99, .type = 0, .offset = 0 };
    qk = stm_key_from_cpu(&q);
    STM_ASSERT_EQ(stm_node_find_child(n, &qk), 2u);

    stm_node_free(n);
}

int main(void)
{
    STM_SUITE("node");
    STM_RUN(test_leaf_insert_find);
    STM_RUN(test_leaf_insert_sorted);
    STM_RUN(test_leaf_update);
    STM_RUN(test_leaf_delete);
    STM_RUN(test_leaf_encode_decode);
    STM_RUN(test_internal_encode_decode);
    STM_RUN(test_leaf_split);
    STM_RUN(test_find_child);
    printf("all passed\n");
    return 0;
}
