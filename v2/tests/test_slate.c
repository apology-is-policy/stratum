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
    /* SLATE-1 + SLATE-2: version, status, event, redraw, log,
     * connection, panels. */
    STM_ASSERT_EQ(cx.n, 7u);
    STM_ASSERT_EQ(strcmp(cx.names[0], "version"),    0);
    STM_ASSERT_EQ(strcmp(cx.names[1], "status"),     0);
    STM_ASSERT_EQ(strcmp(cx.names[2], "event"),      0);
    STM_ASSERT_EQ(strcmp(cx.names[3], "redraw"),     0);
    STM_ASSERT_EQ(strcmp(cx.names[4], "log"),        0);
    STM_ASSERT_EQ(strcmp(cx.names[5], "connection"), 0);
    STM_ASSERT_EQ(strcmp(cx.names[6], "panels"),     0);

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

/* R114 P1-1 regression: /log/tail must serve a full ring of long
 * lines without STM_ERANGE — i.e. the bulk_buf path. The pre-fix
 * implementation overflowed the 4 KiB ss->buf at ~30+ lines. */
STM_TEST(slate_log_tail_full_ring_with_long_lines_renders)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    /* Submit 100 events with ~80-byte payloads — fills the ring at
     * ~106 bytes per emitted line (timestamp prefix ~26 + payload
     * ~80). 100 × 107 ≈ 10.7 KiB, far past STM_SLATE_BODY_MAX (4 KiB)
     * but under STM_SLATE_LOG_TAIL_MAX (64 KiB). The bulk_buf path
     * MUST serve this; pre-R114-fix the materializer returned
     * STM_ERANGE → vops_lopen failed → renderer couldn't read its
     * own log under realistic load. */
    char payload[80];
    memset(payload, 'a', sizeof payload - 1);
    payload[sizeof payload - 1] = '\0';
    for (uint32_t i = 0; i < STM_SLATE_LOG_LINES; i++) {
        payload[0] = (char)('a' + (i % 26));
        payload[1] = (char)('0' + (i % 10));
        STM_ASSERT_OK(stm_slate_submit_event(s, payload,
                                                  sizeof payload - 1));
    }

    char buf[STM_SLATE_LOG_TAIL_MAX];
    uint32_t got = 0;
    STM_ASSERT_OK(read_log_tail(s, buf, sizeof buf, &got));
    STM_ASSERT(got > 4096u);     /* exceeds the old STM_SLATE_BODY_MAX */
    /* The most recent event payload is "%c%caaa..." — verify the
     * last event is somewhere in the body. */
    char wanted[16];
    snprintf(wanted, sizeof wanted, "%c%caaa",
             'a' + ((STM_SLATE_LOG_LINES - 1) % 26),
             '0' + ((STM_SLATE_LOG_LINES - 1) % 10));
    /* memmem is non-portable; do a manual scan. */
    int found = 0;
    size_t wlen = strlen(wanted);
    for (uint32_t i = 0; i + wlen <= got; i++) {
        if (memcmp(buf + i, wanted, wlen) == 0) { found = 1; break; }
    }
    STM_ASSERT(found);

    stm_slate_destroy(s);
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

/* ────────────────────────────────────────────────────────────────────── */
/* P9-SLATE-2: connection + panel state.                                  */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(slate_initial_state_disconnected)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    STM_ASSERT_EQ((int)stm_slate_connected(s), 0);
    char buf[64];
    STM_ASSERT_EQ((unsigned)stm_slate_socket(s, buf, sizeof buf), 0u);
    STM_ASSERT_EQ((unsigned)stm_slate_panel_path(s, 0, buf, sizeof buf), 0u);
    STM_ASSERT_EQ((unsigned)stm_slate_panel_path(s, 1, buf, sizeof buf), 0u);

    stm_slate_destroy(s);
}

STM_TEST(slate_attach_invalid_path_einval)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    /* Oversize path. */
    char big[STM_SLATE_SOCKET_MAX + 8];
    memset(big, 'a', sizeof big);
    STM_ASSERT_EQ(stm_slate_attach(s, big, sizeof big), STM_EINVAL);

    /* Embedded NUL. */
    char nul_path[16] = "/tmp/x\0extra";
    STM_ASSERT_EQ(stm_slate_attach(s, nul_path, 12u), STM_EINVAL);

    /* NULL path with non-zero len. */
    STM_ASSERT_EQ(stm_slate_attach(s, NULL, 5u), STM_EINVAL);

    /* State unchanged on every failed attach. */
    STM_ASSERT_EQ((int)stm_slate_connected(s), 0);

    stm_slate_destroy(s);
}

STM_TEST(slate_attach_empty_path_disconnects)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    /* Empty body is the disconnect verb. From disconnected state, no-op. */
    STM_ASSERT_OK(stm_slate_attach(s, NULL, 0));
    STM_ASSERT_EQ((int)stm_slate_connected(s), 0);
    STM_ASSERT_EQ(stm_slate_version(s), 1u);  /* no-op did not bump */
    stm_slate_destroy(s);
}

STM_TEST(slate_attach_nonexistent_socket_returns_io_or_backend)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const char *bogus = "/tmp/stm_slate_does_not_exist_test.sock";
    /* Just be defensive: any error status is acceptable; what we
     * really want to verify is that state STAYS disconnected after
     * the failure (no half-attach). */
    stm_status rc = stm_slate_attach(s, bogus, strlen(bogus));
    STM_ASSERT(rc != STM_OK);
    STM_ASSERT_EQ((int)stm_slate_connected(s), 0);
    STM_ASSERT_EQ(stm_slate_version(s), 1u);  /* failed dial → no version bump */

    stm_slate_destroy(s);
}

STM_TEST(slate_disconnect_idempotent_when_not_connected)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    STM_ASSERT_OK(stm_slate_disconnect(s));
    STM_ASSERT_EQ((int)stm_slate_connected(s), 0);
    STM_ASSERT_EQ(stm_slate_version(s), 1u);  /* no-op disconnect doesn't bump */
    stm_slate_destroy(s);
}

/* /connection subtree readdir. */
STM_TEST(slate_connection_dir_readdir_emits_socket_connected_attach)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /connection qid: kind = 8. */
    uint64_t conn_qp = ((uint64_t)8) << 56;
    ent_collect cx = {0};
    STM_ASSERT_OK(v->readdir(s, conn_qp, /*cookie=*/0u, ent_cb, &cx));
    STM_ASSERT_EQ(cx.n, 3u);
    STM_ASSERT_EQ(strcmp(cx.names[0], "socket"),    0);
    STM_ASSERT_EQ(strcmp(cx.names[1], "connected"), 0);
    STM_ASSERT_EQ(strcmp(cx.names[2], "attach"),    0);

    stm_slate_destroy(s);
}

/* /panels subtree readdir. */
STM_TEST(slate_panels_dir_readdir_emits_left_and_right)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /panels qid: kind = 12. */
    uint64_t panels_qp = ((uint64_t)12) << 56;
    ent_collect cx = {0};
    STM_ASSERT_OK(v->readdir(s, panels_qp, /*cookie=*/0u, ent_cb, &cx));
    STM_ASSERT_EQ(cx.n, 2u);
    STM_ASSERT_EQ(strcmp(cx.names[0], "left"),  0);
    STM_ASSERT_EQ(strcmp(cx.names[1], "right"), 0);

    /* /panels/left qid: kind = 13 — emits {path, entries, cursor, action}
     * (SLATE-2 path/entries + SLATE-3a cursor/action). */
    uint64_t left_qp = ((uint64_t)13) << 56;
    ent_collect cl = {0};
    STM_ASSERT_OK(v->readdir(s, left_qp, /*cookie=*/0u, ent_cb, &cl));
    STM_ASSERT_EQ(cl.n, 4u);
    STM_ASSERT_EQ(strcmp(cl.names[0], "path"),    0);
    STM_ASSERT_EQ(strcmp(cl.names[1], "entries"), 0);
    STM_ASSERT_EQ(strcmp(cl.names[2], "cursor"),  0);
    STM_ASSERT_EQ(strcmp(cl.names[3], "action"),  0);

    stm_slate_destroy(s);
}

/* /connection/connected when disconnected reads "0\n". */
STM_TEST(slate_connection_connected_read_returns_0_initially)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /connection/connected qid: kind = 10. */
    uint64_t qp = ((uint64_t)10) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    char buf[8];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 77u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    STM_ASSERT_EQ(buf[1], '\n');
    v->clunk(s, 77u, qp);

    stm_slate_destroy(s);
}

/* /connection/socket when disconnected reads just "\n" (one byte). */
STM_TEST(slate_connection_socket_read_returns_newline_initially)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /connection/socket qid: kind = 9. */
    uint64_t qp = ((uint64_t)9) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 77u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    v->clunk(s, 77u, qp);

    stm_slate_destroy(s);
}

/* /panels/left/path when disconnected reads "\n". */
STM_TEST(slate_panel_left_path_read_returns_newline_initially)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /panels/left/path qid: kind = 14. */
    uint64_t qp = ((uint64_t)14) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 77u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 1u);
    STM_ASSERT_EQ(buf[0], '\n');
    v->clunk(s, 77u, qp);

    stm_slate_destroy(s);
}

/* /panels/left/entries when disconnected returns empty body. */
STM_TEST(slate_panel_left_entries_read_returns_empty_when_disconnected)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));

    const stm_lp9_vops *v = stm_slate_vops();
    /* /panels/left/entries qid: kind = 15. */
    uint64_t qp = ((uint64_t)15) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    char buf[64];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 77u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 0u);
    v->clunk(s, 77u, qp);

    stm_slate_destroy(s);
}

/* /connection/attach refuses RDONLY open (write-only kind). */
STM_TEST(slate_conn_attach_rdonly_open_eacces)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    /* /connection/attach qid: kind = 11. */
    uint64_t qp = ((uint64_t)11) << 56;
    STM_ASSERT_EQ(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY), STM_EACCES);
    stm_slate_destroy(s);
}

/* /connection/socket refuses WRONLY open (read-only kind). */
STM_TEST(slate_conn_socket_wronly_open_eacces)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t qp = ((uint64_t)9) << 56;
    STM_ASSERT_EQ(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_WRONLY), STM_EACCES);
    stm_slate_destroy(s);
}

/* ────────────────────────────────────────────────────────────────────── */
/* P9-SLATE-3a: panel cursor + action verbs.                              */
/* ────────────────────────────────────────────────────────────────────── */

/* /panels/X/cursor accepts both RDONLY and WRONLY (RW kind). */
STM_TEST(slate_panel_cursor_accepts_rdonly_and_wronly)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    /* /panels/left/cursor qid: kind = 19. */
    uint64_t qp = ((uint64_t)19) << 56;

    /* RDONLY open ok. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    v->clunk(s, 77u, qp);

    /* WRONLY open ok. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, qp, STM_LP9_O_WRONLY));
    v->clunk(s, 78u, qp);

    /* RDWR open ok. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/79u, qp, STM_LP9_O_RDWR));
    v->clunk(s, 79u, qp);

    stm_slate_destroy(s);
}

/* Initial cursor reads as "0\n". */
STM_TEST(slate_panel_cursor_read_initial_zero)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t qp = ((uint64_t)19) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 77u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    STM_ASSERT_EQ(buf[1], '\n');
    v->clunk(s, 77u, qp);
    stm_slate_destroy(s);
}

/* Writing decimal sets cursor; subsequent read returns the new value. */
STM_TEST(slate_panel_cursor_write_then_read)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t qp = ((uint64_t)19) << 56;

    /* Write "42\n". */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_OK(v->write(s, 77u, qp, 0u, "42\n", 3u, &written));
    STM_ASSERT_EQ(written, 3u);
    v->clunk(s, 77u, qp);

    /* Read back via fresh fid. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, qp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 78u, qp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 3u);
    buf[got] = '\0';
    STM_ASSERT_EQ(strcmp(buf, "42\n"), 0);
    v->clunk(s, 78u, qp);

    stm_slate_destroy(s);
}

/* Writing non-decimal to cursor returns EINVAL; state unchanged. */
STM_TEST(slate_panel_cursor_rejects_non_decimal)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t qp = ((uint64_t)19) << 56;

    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, qp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u, "abc", 3u, &written), STM_EINVAL);
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u, "1a2", 3u, &written), STM_EINVAL);
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u, "-1",  2u, &written), STM_EINVAL);
    /* Empty body refused. */
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u, "",    0u, &written), STM_EINVAL);
    /* Oversized body refused. */
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u,
                              "12345678901234567", 17u, &written), STM_EINVAL);
    /* uint32_t overflow refused. */
    STM_ASSERT_EQ(v->write(s, 77u, qp, 0u,
                              "9999999999", 10u, &written), STM_EINVAL);
    v->clunk(s, 77u, qp);

    stm_slate_destroy(s);
}

/* Action "key Down" increments cursor; "key Up" decrements; clamps at 0. */
STM_TEST(slate_panel_action_key_up_down)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    /* /panels/left/action qid: kind = 20. */
    uint64_t aqp = ((uint64_t)20) << 56;
    /* /panels/left/cursor for verification. */
    uint64_t cqp = ((uint64_t)19) << 56;

    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, aqp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    /* key Down 3 times → cursor = 3. */
    STM_ASSERT_OK(v->write(s, 77u, aqp, 0u, "key Down", 8u, &written));
    STM_ASSERT_OK(v->write(s, 77u, aqp, 0u, "key Down", 8u, &written));
    STM_ASSERT_OK(v->write(s, 77u, aqp, 0u, "key Down", 8u, &written));
    /* key Up 1 time → cursor = 2. */
    STM_ASSERT_OK(v->write(s, 77u, aqp, 0u, "key Up", 6u, &written));
    v->clunk(s, 77u, aqp);

    /* Verify cursor = 2. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, cqp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 78u, cqp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '2');
    STM_ASSERT_EQ(buf[1], '\n');
    v->clunk(s, 78u, cqp);

    /* key Up enough to underflow — should clamp at 0, no error. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/79u, aqp, STM_LP9_O_WRONLY));
    for (int i = 0; i < 5; i++) {
        STM_ASSERT_OK(v->write(s, 79u, aqp, 0u, "key Up", 6u, &written));
    }
    v->clunk(s, 79u, aqp);

    /* Cursor should now be 0. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/80u, cqp, STM_LP9_O_RDONLY));
    got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 80u, cqp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 2u);
    STM_ASSERT_EQ(buf[0], '0');
    v->clunk(s, 80u, cqp);

    stm_slate_destroy(s);
}

/* Action with unknown verb returns ENOTSUPPORTED. */
STM_TEST(slate_panel_action_unknown_verb_enotsup)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t aqp = ((uint64_t)20) << 56;
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, aqp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_EQ(v->write(s, 77u, aqp, 0u, "key Enter", 9u, &written),
                     STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(v->write(s, 77u, aqp, 0u, "noop", 4u, &written),
                     STM_ENOTSUPPORTED);
    /* Empty body refused. */
    STM_ASSERT_EQ(v->write(s, 77u, aqp, 0u, "", 0u, &written), STM_EINVAL);
    v->clunk(s, 77u, aqp);
    stm_slate_destroy(s);
}

/* Cursor write bumps version; key Up at 0 (no-move) does NOT bump. */
STM_TEST(slate_panel_cursor_action_version_bump_semantics)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t cqp = ((uint64_t)19) << 56;
    uint64_t aqp = ((uint64_t)20) << 56;

    uint64_t v0 = stm_slate_version(s);

    /* Write cursor=5 → bumps version. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, cqp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_OK(v->write(s, 77u, cqp, 0u, "5", 1u, &written));
    v->clunk(s, 77u, cqp);
    uint64_t v1 = stm_slate_version(s);
    STM_ASSERT(v1 > v0);

    /* key Down → bumps version. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, aqp, STM_LP9_O_WRONLY));
    STM_ASSERT_OK(v->write(s, 78u, aqp, 0u, "key Down", 8u, &written));
    v->clunk(s, 78u, aqp);
    uint64_t v2 = stm_slate_version(s);
    STM_ASSERT(v2 > v1);

    /* Reset cursor to 0. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/79u, cqp, STM_LP9_O_WRONLY));
    STM_ASSERT_OK(v->write(s, 79u, cqp, 0u, "0", 1u, &written));
    v->clunk(s, 79u, cqp);
    uint64_t v3 = stm_slate_version(s);
    STM_ASSERT(v3 > v2);

    /* key Up at cursor=0 → no-move → version UNCHANGED. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/80u, aqp, STM_LP9_O_WRONLY));
    STM_ASSERT_OK(v->write(s, 80u, aqp, 0u, "key Up", 6u, &written));
    v->clunk(s, 80u, aqp);
    uint64_t v4 = stm_slate_version(s);
    STM_ASSERT_EQ(v4, v3);

    stm_slate_destroy(s);
}

/* Cursor write of same value does NOT bump version (R116 P3-2). */
STM_TEST(slate_panel_cursor_redundant_write_no_version_bump)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t cqp = ((uint64_t)19) << 56;

    /* Initial cursor = 0; write "0" — no-change → no version bump. */
    uint64_t v0 = stm_slate_version(s);
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, cqp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_OK(v->write(s, 77u, cqp, 0u, "0", 1u, &written));
    v->clunk(s, 77u, cqp);
    STM_ASSERT_EQ(stm_slate_version(s), v0);

    /* Now move cursor to 5; bumps. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, cqp, STM_LP9_O_WRONLY));
    STM_ASSERT_OK(v->write(s, 78u, cqp, 0u, "5", 1u, &written));
    v->clunk(s, 78u, cqp);
    uint64_t v1 = stm_slate_version(s);
    STM_ASSERT(v1 > v0);

    /* Write "5" again — no-change → no bump. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/79u, cqp, STM_LP9_O_WRONLY));
    STM_ASSERT_OK(v->write(s, 79u, cqp, 0u, "5", 1u, &written));
    v->clunk(s, 79u, cqp);
    STM_ASSERT_EQ(stm_slate_version(s), v1);

    stm_slate_destroy(s);
}

/* Failed attach leaves prior cursor state untouched. */
STM_TEST(slate_panel_cursor_unchanged_on_failed_attach)
{
    stm_slate *s = NULL;
    STM_ASSERT_OK(stm_slate_create(&s));
    const stm_lp9_vops *v = stm_slate_vops();
    uint64_t cqp = ((uint64_t)19) << 56;

    /* Set cursor=10 from disconnected state. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/77u, cqp, STM_LP9_O_WRONLY));
    uint32_t written = 0;
    STM_ASSERT_OK(v->write(s, 77u, cqp, 0u, "10", 2u, &written));
    v->clunk(s, 77u, cqp);

    /* Attach with bogus path — fails. */
    stm_status arc = stm_slate_attach(s, "/tmp/stm_slate_no_such_dgkjs.sock",
                                          strlen("/tmp/stm_slate_no_such_dgkjs.sock"));
    STM_ASSERT(arc != STM_OK);

    /* Cursor still 10 (failed attach left state untouched). The
     * successful-attach reset path is exercised in test_slate_socket
     * via slate_socket_panel_cursor_resets_on_real_attach_disconnect. */
    STM_ASSERT_OK(v->lopen(s, /*fid=*/78u, cqp, STM_LP9_O_RDONLY));
    char buf[16];
    uint32_t got = (uint32_t)sizeof buf;
    STM_ASSERT_OK(v->read(s, 78u, cqp, 0u, buf, &got));
    STM_ASSERT_EQ(got, 3u);  /* "10\n" */
    v->clunk(s, 78u, cqp);

    stm_slate_destroy(s);
}

STM_TEST_MAIN("slate")
