/* SPDX-License-Identifier: ISC */
/*
 * test_corvus_notify — TLY-A4 wire parser + consumer thread tests.
 *
 * Covers the test matrix from STRATUM-API-V1.md §6.5:
 *   - happy logout (SESSION_CLOSED user matches → stop_flag set)
 *   - cross-user no-op (SESSION_CLOSED for other user → stop_flag NOT set)
 *   - corvus offline (initial connect fails → tolerant timeout → ECORVUSGONE)
 *   - strict-mode EOF → immediate ECORVUSGONE
 *   - caller-driven stop → clean exit
 *
 * Wire-parser unit tests (R138 prep):
 *   - truncated header / payload
 *   - oversize user_len
 *   - control-byte injection in user (R99 P2-1 carry)
 *   - unknown notify_kind (forward-compat tolerance)
 *   - UTF-8 passes through
 *
 * Fake corvus emitter is a Unix-socket listener in the test process.
 */

#include "tharness.h"

#include "../src/cmd/stratumd/corvus_notify.h"

#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Fake corvus emitter.                                                    */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int          listen_fd;
    char         sock_path[128];
    uint8_t    **frames;
    size_t      *frame_lens;
    size_t       n_frames;
    bool         close_after_send;
} fake_corvus;

static void *fake_corvus_thread(void *arg)
{
    fake_corvus *fc = arg;
    int cfd = accept(fc->listen_fd, NULL, NULL);
    if (cfd < 0) return NULL;
    for (size_t i = 0; i < fc->n_frames; i++) {
        ssize_t w = write(cfd, fc->frames[i], fc->frame_lens[i]);
        (void)w;
        usleep(1000);
    }
    if (fc->close_after_send) {
        close(cfd);
    } else {
        uint8_t scratch[16];
        (void)read(cfd, scratch, sizeof scratch);
        close(cfd);
    }
    return NULL;
}

static int fake_corvus_start(fake_corvus *fc, const char *tag)
{
    memset(fc, 0, sizeof *fc);
    snprintf(fc->sock_path, sizeof fc->sock_path,
             "/tmp/stm_corvus_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(fc->sock_path);

    fc->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fc->listen_fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fc->sock_path, sizeof addr.sun_path - 1);
    if (bind(fc->listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fc->listen_fd);
        return -1;
    }
    if (listen(fc->listen_fd, 4) < 0) {
        close(fc->listen_fd);
        (void)unlink(fc->sock_path);
        return -1;
    }
    return 0;
}

static void fake_corvus_stop(fake_corvus *fc)
{
    if (fc->listen_fd >= 0) {
        (void)shutdown(fc->listen_fd, SHUT_RDWR);
        close(fc->listen_fd);
    }
    (void)unlink(fc->sock_path);
}

static uint8_t *make_session_closed_frame(const char *user, size_t *out_len)
{
    size_t user_len = strlen(user);
    size_t payload  = 33u + 1u + user_len;
    size_t total    = 3u + payload;
    uint8_t *buf    = malloc(total);
    if (!buf) return NULL;
    buf[0] = 1;
    buf[1] = (uint8_t)(payload & 0xFFu);
    buf[2] = (uint8_t)((payload >> 8) & 0xFFu);
    memset(buf + 3, 0, 33);
    buf[3 + 33] = (uint8_t)user_len;
    memcpy(buf + 3 + 33 + 1, user, user_len);
    *out_len = total;
    return buf;
}

static int wait_for_stop(atomic_bool *stop, int timeout_ms)
{
    int waited = 0;
    while (waited < timeout_ms) {
        if (atomic_load_explicit(stop, memory_order_acquire)) return 1;
        usleep(10 * 1000);
        waited += 10;
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Wire parser unit tests.                                                 */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_parse_valid_session_closed)
{
    size_t   flen;
    uint8_t *frame = make_session_closed_frame("michael", &flen);
    STM_ASSERT(frame != NULL);

    uint8_t      kind     = 0u;
    const char  *user     = NULL;
    size_t       user_len = 0u;
    stm_status pr = stm_corvus_notify_parse_frame(frame, flen, &kind,
                                                       &user, &user_len);
    STM_ASSERT_OK(pr);
    STM_ASSERT_EQ(kind, 1);
    STM_ASSERT_EQ((long long)user_len, 7LL);
    STM_ASSERT_MEM_EQ(user, "michael", 7);
    free(frame);
}

STM_TEST(corvus_parse_truncated_header)
{
    uint8_t buf[2] = {1, 0};
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(buf, 2u, &kind, &user, &user_len),
                   STM_EPROTOCOL);
}

STM_TEST(corvus_parse_length_mismatch)
{
    uint8_t buf[10] = {1, 100, 0};
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(buf, 10u, &kind, &user, &user_len),
                   STM_EPROTOCOL);
}

STM_TEST(corvus_parse_oversize_user_len)
{
    size_t payload = 33u + 1u + 200u;
    size_t total   = 3u + payload;
    uint8_t *buf   = calloc(1, total);
    STM_ASSERT(buf != NULL);
    buf[0] = 1;
    buf[1] = (uint8_t)(payload & 0xFFu);
    buf[2] = (uint8_t)((payload >> 8) & 0xFFu);
    buf[3 + 33] = 200u;
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(buf, total, &kind, &user, &user_len),
                   STM_EPROTOCOL);
    free(buf);
}

STM_TEST(corvus_parse_user_len_lies)
{
    size_t payload = 33u + 1u + 5u;
    size_t total   = 3u + payload;
    uint8_t *buf   = calloc(1, total);
    STM_ASSERT(buf != NULL);
    buf[0] = 1;
    buf[1] = (uint8_t)(payload & 0xFFu);
    buf[2] = (uint8_t)((payload >> 8) & 0xFFu);
    buf[3 + 33] = 10u;
    memcpy(buf + 3 + 33 + 1, "abcde", 5);
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(buf, total, &kind, &user, &user_len),
                   STM_EPROTOCOL);
    free(buf);
}

STM_TEST(corvus_parse_control_byte_in_user)
{
    size_t   flen;
    uint8_t *frame = make_session_closed_frame("michXel", &flen);
    STM_ASSERT(frame != NULL);
    frame[3 + 33 + 1 + 3] = 0x0a;
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(frame, flen, &kind, &user, &user_len),
                   STM_EPROTOCOL);
    free(frame);
}

STM_TEST(corvus_parse_embedded_nul_in_user)
{
    size_t   flen;
    uint8_t *frame = make_session_closed_frame("michXel", &flen);
    STM_ASSERT(frame != NULL);
    frame[3 + 33 + 1 + 3] = 0x00;
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_ERR(stm_corvus_notify_parse_frame(frame, flen, &kind, &user, &user_len),
                   STM_EPROTOCOL);
    free(frame);
}

STM_TEST(corvus_parse_unknown_kind_tolerated)
{
    uint8_t buf[3] = {42, 0, 0};
    uint8_t kind; const char *user; size_t user_len;
    STM_ASSERT_OK(stm_corvus_notify_parse_frame(buf, 3u, &kind, &user, &user_len));
    STM_ASSERT_EQ(kind, 42);
    STM_ASSERT(user == NULL);
    STM_ASSERT_EQ((long long)user_len, 0LL);
}

STM_TEST(corvus_parse_utf8_passes_through)
{
    const char user[] = "alic\xc3\xa9"; /* "alicé" */
    size_t   flen;
    uint8_t *frame = make_session_closed_frame(user, &flen);
    STM_ASSERT(frame != NULL);
    uint8_t kind; const char *up; size_t ul;
    STM_ASSERT_OK(stm_corvus_notify_parse_frame(frame, flen, &kind, &up, &ul));
    STM_ASSERT_EQ((long long)ul, (long long)strlen(user));
    free(frame);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Consumer end-to-end tests.                                              */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_consumer_happy_logout)
{
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "happy") == 0);
    size_t flen;
    uint8_t *frame = make_session_closed_frame("michael", &flen);
    STM_ASSERT(frame != NULL);
    uint8_t *frames[] = { frame };
    size_t   lens[]   = { flen };
    fc.frames           = frames;
    fc.frame_lens       = lens;
    fc.n_frames         = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path        = fc.sock_path;
    opts.corvus_user        = "michael";
    opts.mode               = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms  = 2000u;
    opts.stop_flag          = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    STM_ASSERT(wait_for_stop(&stop, 3000) == 1);
    STM_ASSERT_OK(stm_corvus_notify_stop(cnc));

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
    free(frame);
}

STM_TEST(corvus_consumer_cross_user_noop)
{
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "cross") == 0);
    size_t flen;
    uint8_t *frame = make_session_closed_frame("susan", &flen);
    STM_ASSERT(frame != NULL);
    uint8_t *frames[] = { frame };
    size_t   lens[]   = { flen };
    fc.frames     = frames;
    fc.frame_lens = lens;
    fc.n_frames   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = fc.sock_path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms = 1000u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    usleep(400 * 1000);
    STM_ASSERT(atomic_load_explicit(&stop, memory_order_acquire) == false);

    atomic_store_explicit(&stop, true, memory_order_release);
    STM_ASSERT_OK(stm_corvus_notify_stop(cnc));

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
    free(frame);
}

STM_TEST(corvus_consumer_initial_offline_strict_fails)
{
    char path[128];
    snprintf(path, sizeof path, "/tmp/stm_corvus_%d_offline.sock",
             (int)getpid());
    (void)unlink(path);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_STRICT;
    opts.notify_timeout_ms = 0u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    STM_ASSERT(wait_for_stop(&stop, 2000) == 1);
    STM_ASSERT_ERR(stm_corvus_notify_stop(cnc), STM_ECORVUSGONE);
}

STM_TEST(corvus_consumer_tolerant_timeout)
{
    char path[128];
    snprintf(path, sizeof path, "/tmp/stm_corvus_%d_tolerant.sock",
             (int)getpid());
    (void)unlink(path);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms = 500u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    STM_ASSERT(wait_for_stop(&stop, 2000) == 1);
    STM_ASSERT_ERR(stm_corvus_notify_stop(cnc), STM_ECORVUSGONE);
}

STM_TEST(corvus_consumer_caller_stop_clean_exit)
{
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "caller") == 0);
    fc.n_frames = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = fc.sock_path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms = 2000u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    usleep(300 * 1000);
    atomic_store_explicit(&stop, true, memory_order_release);

    STM_ASSERT_OK(stm_corvus_notify_stop(cnc));

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
}

STM_TEST(corvus_consumer_strict_eof_escalates)
{
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "strict_eof") == 0);
    fc.n_frames         = 0;
    fc.close_after_send = true;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = fc.sock_path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_STRICT;
    opts.notify_timeout_ms = 2000u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    STM_ASSERT(wait_for_stop(&stop, 2000) == 1);
    STM_ASSERT_ERR(stm_corvus_notify_stop(cnc), STM_ECORVUSGONE);

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
}

STM_TEST(corvus_consumer_no_filter_any_match)
{
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "nofilter") == 0);
    size_t flen;
    uint8_t *frame = make_session_closed_frame("anyone", &flen);
    STM_ASSERT(frame != NULL);
    uint8_t *frames[] = { frame };
    size_t   lens[]   = { flen };
    fc.frames     = frames;
    fc.frame_lens = lens;
    fc.n_frames   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = fc.sock_path;
    opts.corvus_user       = NULL;
    opts.mode              = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms = 2000u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    STM_ASSERT(wait_for_stop(&stop, 3000) == 1);
    STM_ASSERT_OK(stm_corvus_notify_stop(cnc));

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
    free(frame);
}

STM_TEST(corvus_stop_sets_stop_flag)
{
    /* R138 P2-1 close: pin the contract that stm_corvus_notify_stop
     * sets the stop_flag (so callers who want to distinguish caller-
     * initiated vs consumer-initiated must snapshot the flag BEFORE
     * calling stop). */
    fake_corvus fc;
    STM_ASSERT(fake_corvus_start(&fc, "stop_sets_flag") == 0);
    fc.n_frames = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_thread, &fc);

    atomic_bool stop = false;

    stm_corvus_notify_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.socket_path       = fc.sock_path;
    opts.corvus_user       = "michael";
    opts.mode              = STM_CORVUS_NOTIFY_TOLERANT;
    opts.notify_timeout_ms = 2000u;
    opts.stop_flag         = &stop;

    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_OK(stm_corvus_notify_start(&opts, &cnc));

    /* Give consumer time to settle into steady state. */
    usleep(200 * 1000);
    /* Caller has NOT raised stop_flag. */
    STM_ASSERT(atomic_load_explicit(&stop, memory_order_acquire) == false);

    /* stop() should set the flag itself (R138 P2-1). */
    STM_ASSERT_OK(stm_corvus_notify_stop(cnc));
    STM_ASSERT(atomic_load_explicit(&stop, memory_order_acquire) == true);

    pthread_join(tid, NULL);
    fake_corvus_stop(&fc);
}

STM_TEST(corvus_start_arg_validation)
{
    stm_corvus_notify_consumer *cnc = NULL;
    STM_ASSERT_ERR(stm_corvus_notify_start(NULL, &cnc), STM_EINVAL);

    atomic_bool stop = false;
    stm_corvus_notify_opts o;
    memset(&o, 0, sizeof o);
    o.stop_flag = &stop;
    STM_ASSERT_ERR(stm_corvus_notify_start(&o, &cnc), STM_EINVAL);

    memset(&o, 0, sizeof o);
    o.socket_path = "/tmp/whatever";
    STM_ASSERT_ERR(stm_corvus_notify_start(&o, &cnc), STM_EINVAL);

    memset(&o, 0, sizeof o);
    o.socket_path = "/tmp/whatever";
    o.corvus_user = "michael\nthe-injector";
    o.stop_flag   = &stop;
    STM_ASSERT_ERR(stm_corvus_notify_start(&o, &cnc), STM_EINVAL);

    char too_long[64];
    memset(too_long, 'a', sizeof too_long);
    too_long[sizeof too_long - 1] = '\0';
    memset(&o, 0, sizeof o);
    o.socket_path = "/tmp/whatever";
    o.corvus_user = too_long;
    o.stop_flag   = &stop;
    STM_ASSERT_ERR(stm_corvus_notify_start(&o, &cnc), STM_EINVAL);

    STM_ASSERT_OK(stm_corvus_notify_stop(NULL));
}

STM_TEST_MAIN("corvus_notify")
