/* SPDX-License-Identifier: ISC */
/*
 * Repair-log sub-tree tests (Phase 7 chunk P7-15).
 *
 * Coverage:
 *   - Lifecycle: create → close.
 *   - Emit assigns monotonic seq_ids; first emit is 0.
 *   - Iterate yields entries in seq_id order with the expected fields.
 *   - Arg validation: NULL args, out-of-range type / result,
 *     equal target/source replica indices.
 *   - Persistence roundtrip: emit → commit → reopen → load_at →
 *     iterate → equal.
 *   - Idempotent commit: a clean (no emit) repair-log returns the
 *     cached (paddr, csum, next_seq) without re-persisting (R14b
 *     P2-1 pattern; needed for STM_EQUORUM retry safety).
 *   - Tampered next_seq: a UB whose ub_repair_log_next_seq is set
 *     lower than an existing entry's seq_id is rejected at load.
 */

#include "tharness.h"

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/repair_log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES     (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t POOL_UUID[2]   = { 0xCAFEu, 0xBABEu };
static const uint64_t DEVICE_UUID[2] = { 0xDEADu, 0xBEEFu };

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_rl_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_bootstrap *create_fresh_bootstrap(stm_bdev *d)
{
    stm_bootstrap *b = NULL;
    STM_ASSERT_OK(stm_bootstrap_create(d, POOL_UUID, DEVICE_UUID,
                                          TEST_BOOTSTRAP_BYTES, &b));
    return b;
}

/* ========================================================================= */
/* In-RAM only — no bootstrap/persistence required.                            */
/* ========================================================================= */

STM_TEST(repair_log_emit_assigns_monotonic_seq_ids) {
    make_tmp("emit_seq");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    stm_repair_log_index *rl = NULL;
    STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

    stm_repair_log_entry e1 = {
        .timestamp_ns = 1000, .target_paddr = 100, .source_paddr = 200,
        .target_replica_idx = 0, .source_replica_idx = 1,
        .type = STM_REPAIR_TYPE_CSUM_FAIL, .result = STM_REPAIR_RESULT_OK_VERIFIED,
    };
    stm_repair_log_entry e2 = {
        .timestamp_ns = 2000, .target_paddr = 101, .source_paddr = 201,
        .target_replica_idx = 1, .source_replica_idx = 2,
        .type = STM_REPAIR_TYPE_IO_ERR, .result = STM_REPAIR_RESULT_FAIL,
    };

    uint64_t s1 = 99, s2 = 99;
    STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e1, &s1));
    STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e2, &s2));
    STM_ASSERT_EQ(s1, 0u);
    STM_ASSERT_EQ(s2, 1u);
    STM_ASSERT_EQ(stm_repair_log_index_count(rl), 2u);

    stm_repair_log_index_close(rl);
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(repair_log_arg_validation_rejects_invalid_inputs) {
    make_tmp("argval");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    stm_repair_log_index *rl = NULL;
    STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

    stm_repair_log_entry good = {
        .timestamp_ns = 1000, .target_paddr = 100, .source_paddr = 200,
        .target_replica_idx = 0, .source_replica_idx = 1,
        .type = STM_REPAIR_TYPE_CSUM_FAIL, .result = STM_REPAIR_RESULT_OK_VERIFIED,
    };
    uint64_t out = 0;

    /* NULL args. */
    STM_ASSERT_ERR(stm_repair_log_index_emit(NULL, &good, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, NULL, &out), STM_EINVAL);
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &good, NULL), STM_EINVAL);

    /* Out-of-range type. */
    stm_repair_log_entry bad = good;
    bad.type = (stm_repair_type)0;   /* NONE */
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &bad, &out), STM_EINVAL);
    bad.type = (stm_repair_type)99;
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &bad, &out), STM_EINVAL);

    /* Out-of-range result. */
    bad = good;
    bad.result = (stm_repair_result)0;
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &bad, &out), STM_EINVAL);
    bad.result = (stm_repair_result)99;
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &bad, &out), STM_EINVAL);

    /* bptr.tla::LogIntegrity: target ≠ source. */
    bad = good;
    bad.target_replica_idx = 1;
    bad.source_replica_idx = 1;
    STM_ASSERT_ERR(stm_repair_log_index_emit(rl, &bad, &out), STM_EINVAL);

    /* No emit happened on any failure → count stays 0. */
    STM_ASSERT_EQ(stm_repair_log_index_count(rl), 0u);

    stm_repair_log_index_close(rl);
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

typedef struct {
    size_t                   n;
    stm_repair_log_entry     entries[8];
} iter_collect_ctx;

static int iter_collect_cb(const stm_repair_log_entry *e, void *ctx_)
{
    iter_collect_ctx *c = ctx_;
    if (c->n >= sizeof c->entries / sizeof *c->entries) return 1;
    c->entries[c->n++] = *e;
    return 0;
}

STM_TEST(repair_log_iter_yields_entries_in_seq_order) {
    make_tmp("iter");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    stm_repair_log_index *rl = NULL;
    STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

    for (int i = 0; i < 5; i++) {
        stm_repair_log_entry e = {
            .timestamp_ns = (uint64_t)(1000 + i),
            .target_paddr = (uint64_t)(100 + i),
            .source_paddr = (uint64_t)(200 + i),
            .target_replica_idx = (uint8_t)(i % 4),
            .source_replica_idx = (uint8_t)((i + 1) % 4),
            .type = (i & 1) ? STM_REPAIR_TYPE_IO_ERR
                            : STM_REPAIR_TYPE_CSUM_FAIL,
            .result = (i == 4) ? STM_REPAIR_RESULT_FAIL
                               : STM_REPAIR_RESULT_OK_VERIFIED,
        };
        uint64_t out = 0;
        STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out));
        STM_ASSERT_EQ(out, (uint64_t)i);
    }

    iter_collect_ctx c = {0};
    STM_ASSERT_OK(stm_repair_log_index_iter(rl, iter_collect_cb, &c));
    STM_ASSERT_EQ(c.n, 5u);
    for (size_t i = 0; i < c.n; i++) {
        STM_ASSERT_EQ(c.entries[i].seq_id,       (uint64_t)i);
        STM_ASSERT_EQ(c.entries[i].timestamp_ns, (uint64_t)(1000 + i));
        STM_ASSERT_EQ(c.entries[i].target_paddr, (uint64_t)(100 + i));
        STM_ASSERT_EQ(c.entries[i].source_paddr, (uint64_t)(200 + i));
    }

    stm_repair_log_index_close(rl);
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Persistence roundtrip.                                                     */
/* ========================================================================= */

STM_TEST(repair_log_persists_across_close_reopen) {
    make_tmp("persist");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    /* Phase 1: create + emit + commit. */
    uint64_t persisted_paddr  = 0;
    uint8_t  persisted_csum[32] = {0};
    uint64_t persisted_next_seq = 0;
    {
        stm_repair_log_index *rl = NULL;
        STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

        for (int i = 0; i < 3; i++) {
            stm_repair_log_entry e = {
                .timestamp_ns = (uint64_t)(7777 + i),
                .target_paddr = (uint64_t)(0x1000u + i * 0x100u),
                .source_paddr = (uint64_t)(0x2000u + i * 0x100u),
                .target_replica_idx = 0, .source_replica_idx = 1,
                .type = STM_REPAIR_TYPE_CSUM_FAIL,
                .result = STM_REPAIR_RESULT_OK_VERIFIED,
            };
            uint64_t out = 0;
            STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out));
        }

        STM_ASSERT_OK(stm_repair_log_index_commit(rl, /*committed_gen=*/1,
                                                       &persisted_paddr,
                                                       persisted_csum,
                                                       &persisted_next_seq));
        STM_ASSERT(persisted_paddr != 0);
        STM_ASSERT_EQ(persisted_next_seq, 3u);

        /* Bootstrap commit happens inside repair_log_commit (the
         * subsystem persists its own bitmap reservations). */
        stm_repair_log_index_close(rl);
    }

    /* Close + reopen the bdev to flush all caches. */
    stm_bootstrap_close(boot);
    stm_bdev_close(d);

    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    boot = NULL;
    STM_ASSERT_OK(stm_bootstrap_open(d, &boot));

    /* Phase 2: open + load_at + iterate. */
    {
        stm_repair_log_index *rl = NULL;
        STM_ASSERT_OK(stm_repair_log_index_open(d, boot, &rl));

        STM_ASSERT_OK(stm_repair_log_index_load_at(rl, persisted_paddr,
                                                       persisted_csum,
                                                       persisted_next_seq));
        STM_ASSERT_EQ(stm_repair_log_index_count(rl), 3u);

        iter_collect_ctx c = {0};
        STM_ASSERT_OK(stm_repair_log_index_iter(rl, iter_collect_cb, &c));
        STM_ASSERT_EQ(c.n, 3u);
        for (size_t i = 0; i < c.n; i++) {
            STM_ASSERT_EQ(c.entries[i].seq_id,       (uint64_t)i);
            STM_ASSERT_EQ(c.entries[i].timestamp_ns, (uint64_t)(7777 + i));
            STM_ASSERT_EQ(c.entries[i].target_paddr,
                            (uint64_t)(0x1000u + i * 0x100u));
            STM_ASSERT_EQ(c.entries[i].source_paddr,
                            (uint64_t)(0x2000u + i * 0x100u));
            STM_ASSERT_EQ(c.entries[i].type, STM_REPAIR_TYPE_CSUM_FAIL);
            STM_ASSERT_EQ(c.entries[i].result, STM_REPAIR_RESULT_OK_VERIFIED);
        }

        /* Next emit picks up where the persisted view left off. */
        stm_repair_log_entry post = {
            .timestamp_ns = 9999, .target_paddr = 0x9000, .source_paddr = 0xA000,
            .target_replica_idx = 2, .source_replica_idx = 3,
            .type = STM_REPAIR_TYPE_IO_ERR,
            .result = STM_REPAIR_RESULT_OK_VERIFIED,
        };
        uint64_t out = 0;
        STM_ASSERT_OK(stm_repair_log_index_emit(rl, &post, &out));
        STM_ASSERT_EQ(out, 3u);

        stm_repair_log_index_close(rl);
    }

    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(repair_log_idempotent_commit_when_clean) {
    make_tmp("idempot");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    stm_repair_log_index *rl = NULL;
    STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

    stm_repair_log_entry e = {
        .timestamp_ns = 1, .target_paddr = 1, .source_paddr = 2,
        .target_replica_idx = 0, .source_replica_idx = 1,
        .type = STM_REPAIR_TYPE_CSUM_FAIL,
        .result = STM_REPAIR_RESULT_OK_VERIFIED,
    };
    uint64_t out = 0;
    STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out));

    uint64_t paddr1 = 0, paddr2 = 0;
    uint8_t  csum1[32] = {0}, csum2[32] = {0};
    uint64_t seq1 = 0, seq2 = 0;
    STM_ASSERT_OK(stm_repair_log_index_commit(rl, 5,
                                                  &paddr1, csum1, &seq1));
    /* Second commit at a different gen with NO new emit: idempotent
     * — same paddr, csum, next_seq. */
    STM_ASSERT_OK(stm_repair_log_index_commit(rl, 7,
                                                  &paddr2, csum2, &seq2));
    STM_ASSERT_EQ(paddr1, paddr2);
    STM_ASSERT_MEM_EQ(csum1, csum2, 32);
    STM_ASSERT_EQ(seq1, seq2);

    stm_repair_log_index_close(rl);
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(repair_log_load_rejects_tampered_next_seq) {
    /* A tampered ub_repair_log_next_seq set ≤ an existing entry's
     * seq_id surfaces as STM_ECORRUPT during load_at — defends
     * against a tamper that resets the counter and would let the
     * next emit collide with persisted entries' seq_ids. */
    make_tmp("tamper");
    stm_bdev *d = open_fresh_device();
    stm_bootstrap *boot = create_fresh_bootstrap(d);

    uint64_t persisted_paddr  = 0;
    uint8_t  persisted_csum[32] = {0};
    {
        stm_repair_log_index *rl = NULL;
        STM_ASSERT_OK(stm_repair_log_index_create(d, boot, &rl));

        for (int i = 0; i < 3; i++) {
            stm_repair_log_entry e = {
                .timestamp_ns = (uint64_t)i,
                .target_paddr = 100, .source_paddr = 200,
                .target_replica_idx = 0, .source_replica_idx = 1,
                .type = STM_REPAIR_TYPE_CSUM_FAIL,
                .result = STM_REPAIR_RESULT_OK_VERIFIED,
            };
            uint64_t out = 0;
            STM_ASSERT_OK(stm_repair_log_index_emit(rl, &e, &out));
        }
        uint64_t seq_unused = 0;
        STM_ASSERT_OK(stm_repair_log_index_commit(rl, 1, &persisted_paddr,
                                                       persisted_csum,
                                                       &seq_unused));
        stm_repair_log_index_close(rl);
    }

    /* Reopen + load_at with a tampered starting_seq_id (1; valid
     * persisted next_seq is 3, the loaded entries have max seq=2,
     * so a tamper to 1 means starting_seq_id <= max_seq=2 → reject). */
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bootstrap_open(d, &boot));

    stm_repair_log_index *rl = NULL;
    STM_ASSERT_OK(stm_repair_log_index_open(d, boot, &rl));
    STM_ASSERT_ERR(stm_repair_log_index_load_at(rl, persisted_paddr,
                                                    persisted_csum,
                                                    /*tampered=*/1),
                       STM_ECORRUPT);

    stm_repair_log_index_close(rl);
    stm_bootstrap_close(boot);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("repair_log")
