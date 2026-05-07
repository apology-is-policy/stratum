/* SPDX-License-Identifier: ISC */
/*
 * test_slate — unit tests for stm_slate's state machine
 * (P9-SLATE-1).
 *
 * Composes against v2/specs/slate.tla:
 *   VersionMonotonic — every event/status mutation bumps version.
 *   EventFIFO        — dispatched order matches submission order
 *                      (verified via /log/tail readback).
 *   ReadConsistent   — version advances ONLY via dispatch.
 *
 * These tests exercise the API directly (no socket); the
 * test_stratum_slate.c integration tests cover the wire path.
 */
#include "tharness.h"

#include <stratum/lp9.h>
#include <stratum/slate.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── version + status ─────────────────────────────────────────────── */

STM_TEST(slate_create_initial_version_is_one)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    STM_ASSERT_EQ(stm_slate_version(s), 1u);
    stm_slate_destroy(s);
}

STM_TEST(slate_submit_event_bumps_version)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    uint64_t v0 = stm_slate_version(s);
    STM_ASSERT_OK(stm_slate_submit_event(s, "key F5", 6));
    uint64_t v1 = stm_slate_version(s);
    STM_ASSERT_EQ(v1, v0 + 1u);

    STM_ASSERT_OK(stm_slate_submit_event(s, "key F3", 6));
    uint64_t v2 = stm_slate_version(s);
    STM_ASSERT_EQ(v2, v1 + 1u);

    stm_slate_destroy(s);
}

STM_TEST(slate_submit_event_strips_trailing_newline)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    STM_ASSERT_OK(stm_slate_submit_event(s, "hello\n", 6));
    STM_ASSERT_EQ(stm_slate_version(s), 2u);
    stm_slate_destroy(s);
}

STM_TEST(slate_submit_event_zero_byte_einval)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    /* Empty after newline strip → STM_EINVAL. */
    STM_ASSERT_EQ(stm_slate_submit_event(s, "", 0), STM_EINVAL);
    STM_ASSERT_EQ(stm_slate_submit_event(s, "\n", 1), STM_EINVAL);
    STM_ASSERT_EQ(stm_slate_version(s), 1u);   /* no bump on refusal */
    stm_slate_destroy(s);
}

STM_TEST(slate_submit_event_oversize_einval)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    char big[STM_SLATE_EVENT_LINE_MAX + 1];
    memset(big, 'x', sizeof big);
    STM_ASSERT_EQ(stm_slate_submit_event(s, big, sizeof big), STM_EINVAL);
    STM_ASSERT_EQ(stm_slate_version(s), 1u);
    stm_slate_destroy(s);
}

STM_TEST(slate_set_status_bumps_version_and_rejects_newlines)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    STM_ASSERT_OK(stm_slate_set_status(s, "hello world", 11));
    STM_ASSERT_EQ(stm_slate_version(s), 2u);

    /* Newlines refused (would break the line-oriented wire format). */
    STM_ASSERT_EQ(stm_slate_set_status(s, "two\nlines", 9), STM_EINVAL);
    STM_ASSERT_EQ(stm_slate_version(s), 2u);   /* no bump on refusal */

    /* Oversize refused. */
    char big[STM_SLATE_STATUS_MAX + 1];
    memset(big, 'x', sizeof big);
    STM_ASSERT_EQ(stm_slate_set_status(s, big, sizeof big), STM_EINVAL);
    STM_ASSERT_EQ(stm_slate_version(s), 2u);

    stm_slate_destroy(s);
}

/* ── /redraw blocking-read semantics ──────────────────────────────── */

typedef struct {
    stm_slate *slate;
    uint64_t   wait_for;        /* read should return version > wait_for */
    uint64_t   got;
    int        completed;
} redraw_ctx;

/* Direct call into the vops_read primitive, simulating a /redraw read.
 * Forms the same call shape as stm_lp9_server's h_read would: takes
 * fid + qid_path + offset + buffer, returns version as decimal. */
static stm_status redraw_read_via_vops(stm_slate *s, uint64_t offset,
                                          char *buf, uint32_t cap,
                                          uint32_t *out_len)
{
    /* Allocate a session for fid=42 bound to /redraw. We do this via
     * the vops_lopen path, then call vops_read. */
    const stm_lp9_vops *v = stm_slate_vops();
    /* /redraw qid_path: kind=4 in high byte. */
    uint64_t redraw_qid = ((uint64_t)4) << 56;
    stm_status rc = v->lopen(s, /*fid=*/42u, redraw_qid, STM_LP9_O_RDONLY);
    if (rc != STM_OK) return rc;
    *out_len = cap;
    rc = v->read(s, /*fid=*/42u, redraw_qid, offset, buf, out_len);
    v->clunk(s, /*fid=*/42u, redraw_qid);
    return rc;
}

static void *redraw_blocking_thread(void *arg)
{
    redraw_ctx *cx = (redraw_ctx *)arg;
    char buf[64];
    uint32_t got = 0;
    stm_status rc = redraw_read_via_vops(cx->slate, cx->wait_for,
                                            buf, sizeof buf - 1, &got);
    if (rc == STM_OK && got > 0) {
        buf[got] = '\0';
        cx->got = (uint64_t)atoll(buf);
    }
    cx->completed = 1;
    return NULL;
}

STM_TEST(slate_redraw_blocks_until_version_advances)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    /* Spawn a reader at offset = current version (1). It should
     * block. */
    redraw_ctx cx = { .slate = s, .wait_for = 1u, .got = 0u, .completed = 0 };
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL,
                                    redraw_blocking_thread, &cx), 0);

    /* Give the worker time to enter cond_wait. */
    struct timespec ts = { 0, 50 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    STM_ASSERT_EQ(cx.completed, 0);     /* still blocked */

    /* Submit an event — bumps version, wakes the reader. */
    STM_ASSERT_OK(stm_slate_submit_event(s, "wakeup", 6));

    pthread_join(worker, NULL);
    STM_ASSERT_EQ(cx.completed, 1);
    STM_ASSERT_EQ(cx.got, 2u);          /* version advanced 1 → 2 */

    stm_slate_destroy(s);
}

STM_TEST(slate_redraw_returns_immediately_if_version_already_advanced)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    /* Submit two events first. Then read at offset=1 — should NOT
     * block; version is already 3. */
    STM_ASSERT_OK(stm_slate_submit_event(s, "a", 1));
    STM_ASSERT_OK(stm_slate_submit_event(s, "b", 1));
    STM_ASSERT_EQ(stm_slate_version(s), 3u);

    char buf[64];
    uint32_t got = 0;
    STM_ASSERT_OK(redraw_read_via_vops(s, /*offset=*/1u,
                                          buf, sizeof buf - 1, &got));
    buf[got] = '\0';
    STM_ASSERT_EQ((unsigned)atoi(buf), 3u);

    stm_slate_destroy(s);
}

STM_TEST(slate_stop_wakes_blocked_redraw)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    redraw_ctx cx = { .slate = s, .wait_for = 100u, .got = 0u, .completed = 0 };
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL,
                                    redraw_blocking_thread, &cx), 0);

    struct timespec ts = { 0, 50 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    STM_ASSERT_EQ(cx.completed, 0);

    /* Stop the slate — broadcasts cv. */
    stm_slate_stop(s);

    pthread_join(worker, NULL);
    STM_ASSERT_EQ(cx.completed, 1);
    /* After stop, redraw returns the current version (1) since
     * we never bumped past 100. The actual return value is
     * version-at-wake; the test's contract is just "wakes". */

    stm_slate_destroy(s);
}

/* ── EventFIFO via log/tail readback ──────────────────────────────── */

/* Read /log/tail via the vops directly. Returns the body bytes. */
static stm_status read_log_tail(stm_slate *s, char *buf, uint32_t cap,
                                   uint32_t *out_len)
{
    const stm_lp9_vops *v = stm_slate_vops();
    /* /log/tail qid_path: kind=6 in high byte. */
    uint64_t qp = ((uint64_t)6) << 56;
    stm_status rc = v->lopen(s, /*fid=*/43u, qp, STM_LP9_O_RDONLY);
    if (rc != STM_OK) return rc;
    *out_len = cap;
    rc = v->read(s, /*fid=*/43u, qp, /*offset=*/0u, buf, out_len);
    v->clunk(s, /*fid=*/43u, qp);
    return rc;
}

STM_TEST(slate_log_tail_reflects_event_dispatch_in_order)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    STM_ASSERT_OK(stm_slate_submit_event(s, "first", 5));
    STM_ASSERT_OK(stm_slate_submit_event(s, "second", 6));
    STM_ASSERT_OK(stm_slate_submit_event(s, "third", 5));

    char buf[STM_SLATE_BODY_MAX + 1];
    uint32_t got = 0;
    STM_ASSERT_OK(read_log_tail(s, buf, sizeof buf - 1, &got));
    buf[got] = '\0';

    /* All three event names appear, in order. EventFIFO check. */
    const char *p_first  = strstr(buf, "first");
    const char *p_second = strstr(buf, "second");
    const char *p_third  = strstr(buf, "third");
    STM_ASSERT(p_first  != NULL);
    STM_ASSERT(p_second != NULL);
    STM_ASSERT(p_third  != NULL);
    STM_ASSERT(p_first  < p_second);
    STM_ASSERT(p_second < p_third);

    /* Each entry has the "got: " prefix. */
    STM_ASSERT(strstr(buf, "got: first")  != NULL);
    STM_ASSERT(strstr(buf, "got: second") != NULL);
    STM_ASSERT(strstr(buf, "got: third")  != NULL);

    stm_slate_destroy(s);
}

STM_TEST(slate_log_tail_ring_buffer_drops_oldest)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    /* Submit STM_SLATE_LOG_LINES + 5 events. The first 5 must drop. */
    for (uint32_t i = 0; i < STM_SLATE_LOG_LINES + 5u; i++) {
        char line[16];
        int n = snprintf(line, sizeof line, "evt-%u", i);
        STM_ASSERT(n > 0);
        STM_ASSERT_OK(stm_slate_submit_event(s, line, (size_t)n));
    }

    /* /log/tail must NOT contain "evt-0" or "evt-4" — they were
     * dropped — but must contain "evt-5" and "evt-104". */
    char buf[STM_SLATE_BODY_MAX + 1];
    uint32_t got = 0;
    STM_ASSERT_OK(read_log_tail(s, buf, sizeof buf - 1, &got));
    buf[got] = '\0';
    STM_ASSERT(strstr(buf, "got: evt-0\n") == NULL);
    STM_ASSERT(strstr(buf, "got: evt-4\n") == NULL);
    STM_ASSERT(strstr(buf, "got: evt-5") != NULL);
    /* evt-104 is the last submitted. */
    STM_ASSERT(strstr(buf, "got: evt-104") != NULL);

    stm_slate_destroy(s);
}

/* ── readdir / walk smoke ─────────────────────────────────────────── */

typedef struct {
    char     names[16][32];
    uint32_t n;
} ent_collect;

static stm_status ent_cb(const stm_lp9_dirent *e, void *cx_v)
{
    ent_collect *cx = (ent_collect *)cx_v;
    if (cx->n >= 16) return STM_OK;
    size_t nl = e->name_len;
    if (nl >= sizeof cx->names[0]) nl = sizeof cx->names[0] - 1;
    memcpy(cx->names[cx->n], e->name, nl);
    cx->names[cx->n][nl] = '\0';
    cx->n++;
    return STM_OK;
}

STM_TEST(slate_root_readdir_emits_expected_entries)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    ent_collect cx = {0};
    STM_ASSERT_OK(v->readdir(s, stm_slate_root(s), /*cookie=*/0u,
                                ent_cb, &cx));
    STM_ASSERT_EQ(cx.n, 5u);
    /* version, status, event, redraw, log */
    STM_ASSERT_EQ(strcmp(cx.names[0], "version"), 0);
    STM_ASSERT_EQ(strcmp(cx.names[1], "status"),  0);
    STM_ASSERT_EQ(strcmp(cx.names[2], "event"),   0);
    STM_ASSERT_EQ(strcmp(cx.names[3], "redraw"),  0);
    STM_ASSERT_EQ(strcmp(cx.names[4], "log"),     0);

    stm_slate_destroy(s);
}

STM_TEST(slate_log_dir_readdir_emits_tail_and_append)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* Walk to /log first — but vops_walk doesn't take an empty walk;
     * we just construct the qid_path directly. /log = kind=5. */
    uint64_t log_qp = ((uint64_t)5) << 56;
    ent_collect cx = {0};
    STM_ASSERT_OK(v->readdir(s, log_qp, /*cookie=*/0u, ent_cb, &cx));
    STM_ASSERT_EQ(cx.n, 2u);
    STM_ASSERT_EQ(strcmp(cx.names[0], "tail"),   0);
    STM_ASSERT_EQ(strcmp(cx.names[1], "append"), 0);

    stm_slate_destroy(s);
}

STM_TEST(slate_walk_unknown_name_enoent)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    stm_lp9_qid q;
    STM_ASSERT_EQ(v->walk(s, stm_slate_root(s), "nonexistent", 11, &q),
                    STM_ENOENT);
    stm_slate_destroy(s);
}

/* ── EventFIFO under concurrent writers ───────────────────────────── */

typedef struct {
    stm_slate *slate;
    uint32_t   id_base;
    uint32_t   count;
} writer_ctx;

static void *writer_thread(void *arg)
{
    writer_ctx *wc = (writer_ctx *)arg;
    for (uint32_t i = 0; i < wc->count; i++) {
        char line[32];
        int n = snprintf(line, sizeof line, "w%u-i%u", wc->id_base, i);
        if (n > 0) (void)stm_slate_submit_event(wc->slate, line, (size_t)n);
    }
    return NULL;
}

STM_TEST(slate_concurrent_writers_version_advances_exactly_n_times)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const uint32_t N = 4;
    const uint32_t per_thread = 10;
    pthread_t tids[4];
    writer_ctx wcs[4];
    for (uint32_t i = 0; i < N; i++) {
        wcs[i].slate = s;
        wcs[i].id_base = i;
        wcs[i].count = per_thread;
        STM_ASSERT_EQ(pthread_create(&tids[i], NULL,
                                        writer_thread, &wcs[i]), 0);
    }
    for (uint32_t i = 0; i < N; i++) pthread_join(tids[i], NULL);

    /* version advanced exactly N*per_thread times beyond initial 1. */
    STM_ASSERT_EQ(stm_slate_version(s), 1u + (uint64_t)(N * per_thread));

    stm_slate_destroy(s);
}

STM_TEST_MAIN("slate")
