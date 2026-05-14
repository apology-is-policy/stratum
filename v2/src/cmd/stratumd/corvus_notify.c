/* SPDX-License-Identifier: ISC */
/*
 * stratumd ↔ corvus notify-Spoor consumer (TLY-A4).
 *
 * See `corvus_notify.h` for the architecture summary, trust boundaries,
 * and the bilateral contract reference (STRATUM-API-V1.md §6).
 *
 * Spec: composes against `v2/specs/eviction.tla` (the notify-arrive →
 * stop-flag-set → unmount-drain sequence).
 */

#include "corvus_notify.h"

#include <stratum/ctl.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Default tolerant-mode reconnect window. STRATUM-API-V1.md §6.3 Q12. */
#define CORVUS_DEFAULT_TIMEOUT_MS   (30u * 1000u)

/* Open-retry backoff during initial-connect / tolerant reconnect. */
#define CORVUS_OPEN_RETRY_INTERVAL_MS  200u

/* Per-poll tick when waiting for bytes (so stop_flag is observed
 * promptly regardless of corvus quiescence). */
#define CORVUS_POLL_TICK_MS         200

struct stm_corvus_notify_consumer {
    pthread_t       tid;
    atomic_bool     started;        /* set true after pthread_create succeeds */
    stm_status      rc;             /* worker writes; stop() reads after join */

    /* Snapshotted opts (caller-owned strings are duped here so the
     * consumer is robust against caller-side lifecycle). */
    char           *socket_path;
    char           *corvus_user;
    size_t          corvus_user_len;
    stm_corvus_notify_mode mode;
    uint32_t        timeout_ms;
    atomic_bool    *stop_flag;
    struct stm_ctl *ctl;
};

/* ────────────────────────────────────────────────────────────────────── */
/* Wire parser. Public-surface-callable for tests; the consumer thread   */
/* also calls it directly.                                                */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_notify_parse_frame(const uint8_t *buf, size_t buf_len,
                                              uint8_t *out_kind,
                                              const char **out_user,
                                              size_t *out_user_len)
{
    if (!buf || !out_kind || !out_user || !out_user_len)
        return STM_EINVAL;

    *out_kind     = 0u;
    *out_user     = NULL;
    *out_user_len = 0u;

    if (buf_len < STM_CORVUS_NOTIFY_HDR_LEN)
        return STM_EPROTOCOL;

    uint8_t  kind        = buf[0];
    uint16_t payload_len = (uint16_t)((uint16_t)buf[1] |
                                          ((uint16_t)buf[2] << 8));

    /* Frame-length consistency: 3 header bytes + payload_len = buf_len. */
    if ((size_t)STM_CORVUS_NOTIFY_HDR_LEN + (size_t)payload_len != buf_len)
        return STM_EPROTOCOL;

    /* Per-kind body shape. */
    if (kind == STM_CORVUS_NOTIFY_SESSION_CLOSED) {
        /* Layout: [3..36) token = 33 bytes, [36] user_len = 1 byte,
         * [37..) user = user_len bytes. */
        if (payload_len < STM_CORVUS_NOTIFY_TOKEN_LEN + 1u)
            return STM_EPROTOCOL;

        size_t user_len = buf[STM_CORVUS_NOTIFY_HDR_LEN +
                                  STM_CORVUS_NOTIFY_TOKEN_LEN];

        if (user_len > STM_CORVUS_USER_MAX)
            return STM_EPROTOCOL;

        /* user must fit in payload after token + user_len bytes. */
        if ((size_t)payload_len !=
                STM_CORVUS_NOTIFY_TOKEN_LEN + 1u + user_len)
            return STM_EPROTOCOL;

        const uint8_t *user_p =
            buf + STM_CORVUS_NOTIFY_HDR_LEN +
                  STM_CORVUS_NOTIFY_TOKEN_LEN + 1u;

        /* R99 P2-1 carry: refuse control bytes + embedded NUL in the
         * user field. UTF-8 multi-byte (≥ 0x80) passes through. */
        for (size_t i = 0; i < user_len; i++) {
            uint8_t b = user_p[i];
            if (b == 0u || b < 0x20u || b == 0x7Fu)
                return STM_EPROTOCOL;
        }

        *out_kind     = kind;
        *out_user     = (const char *)user_p;
        *out_user_len = user_len;
        return STM_OK;
    }

    /* Unknown notify_kind: forward-compat tolerance. Body shape is
     * not parsed; the caller treats this as a no-op. The frame is
     * still well-formed (size matches header) so we return STM_OK. */
    *out_kind     = kind;
    *out_user     = NULL;
    *out_user_len = 0u;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Robust I/O helpers (mirror stratumd's serve.c discipline).             */
/* ────────────────────────────────────────────────────────────────────── */

static bool stop_observed(const stm_corvus_notify_consumer *c)
{
    return c->stop_flag &&
        atomic_load_explicit(c->stop_flag, memory_order_acquire);
}

/* Block until either at least 1 byte is readable, fd hits POLLERR/HUP,
 * or stop_flag is set. Returns:
 *   0 → bytes ready
 *   1 → fd closed (EOF / POLLERR / POLLHUP / POLLNVAL)
 *  -1 → stop_flag observed
 *  -errno → poll() error
 *
 * Uses CORVUS_POLL_TICK_MS so the consumer responds to stop_flag
 * within ~200 ms even when corvus is quiescent. */
static int wait_readable(int fd, const stm_corvus_notify_consumer *c)
{
    while (1) {
        if (stop_observed(c)) return -1;
        struct pollfd pfd = { fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, CORVUS_POLL_TICK_MS);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (prc == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return 1;
        if (pfd.revents & POLLIN) return 0;
    }
}

/* Read exactly `len` bytes. Returns:
 *   0  → success
 *  +1  → clean EOF (peer closed) before/at byte 0
 *  -1  → stop_flag observed mid-read
 *  -2  → EOF mid-message (truncated)
 *  -errno → I/O error
 */
static int read_full(int fd, void *buf, size_t len,
                     const stm_corvus_notify_consumer *c)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   done = 0;
    while (done < len) {
        int wrc = wait_readable(fd, c);
        if (wrc == -1) return -1;
        if (wrc == 1)  return (done == 0) ? 1 : -2;
        if (wrc < 0)   return wrc;

        ssize_t n = read(fd, p + done, len - done);
        if (n == 0) return (done == 0) ? 1 : -2;
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -errno;
        }
        done += (size_t)n;
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Connect helpers.                                                       */
/* ────────────────────────────────────────────────────────────────────── */

static int try_connect(const char *path)
{
    if (!path || !*path) return -EINVAL;
    if (strlen(path) >= sizeof((struct sockaddr_un *)0)->sun_path)
        return -ENAMETOOLONG;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -errno;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    /* CLOEXEC defensively (we never fork-exec, but a future binary
     * with a child-spawn path shouldn't leak the notify fd). */
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    return fd;
}

/* Open with retry, capped by `budget_ms` (0 = infinite). Returns:
 *   fd ≥ 0       → connected
 *   -1           → stop_flag observed during retry
 *   -2           → budget exhausted
 *   -errno       → non-retryable error
 */
static int open_with_retry(const stm_corvus_notify_consumer *c,
                              uint32_t budget_ms)
{
    uint32_t spent = 0u;
    while (1) {
        if (stop_observed(c)) return -1;
        int fd = try_connect(c->socket_path);
        if (fd >= 0) return fd;
        /* Treat ENOENT / ECONNREFUSED / EAGAIN as "corvus not up
         * yet". Anything else (EACCES, ENAMETOOLONG, ...) is fatal. */
        if (fd != -ENOENT && fd != -ECONNREFUSED &&
                fd != -EAGAIN && fd != -EINTR) {
            return fd;
        }
        if (budget_ms > 0u && spent >= budget_ms) return -2;

        /* Sleep CORVUS_OPEN_RETRY_INTERVAL_MS in poll-tick chunks
         * so stop_flag is still observed promptly. */
        uint32_t step = CORVUS_OPEN_RETRY_INTERVAL_MS;
        if (budget_ms > 0u && (budget_ms - spent) < step)
            step = budget_ms - spent;
        struct pollfd dummy = { -1, 0, 0 };
        (void)poll(&dummy, 0, (int)step);
        spent += step;
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* Worker thread.                                                         */
/* ────────────────────────────────────────────────────────────────────── */

__attribute__((format(printf, 2, 3)))
static void log_event(stm_corvus_notify_consumer *c, const char *fmt, ...)
{
    if (!c->ctl) return;
    /* Format into a stack buffer first so we can route through the
     * caller-stable %s pattern accepted by stm_ctl_log_event. */
    char line[256];
    va_list ap;
    va_start(ap, fmt);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    int n = vsnprintf(line, sizeof line, fmt, ap);
#pragma GCC diagnostic pop
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof line) {
        /* Truncate marker so audit reader sees the line was clipped. */
        line[sizeof line - 1] = '\0';
    }
    stm_ctl_log_event(c->ctl, "%s", line);
}

/* Set the daemon's stop flag. Memory order matches stratumd's
 * existing signal-handler discipline (release on store; accept
 * loops acquire on load). */
static void signal_stop(stm_corvus_notify_consumer *c)
{
    if (c->stop_flag)
        atomic_store_explicit(c->stop_flag, true, memory_order_release);
}

/* Process one frame's worth of bytes. Returns:
 *   STM_OK           → consumer continues
 *   STM_OK + stop set → matching SESSION_CLOSED handled (caller checks stop_flag)
 *   STM_EPROTOCOL    → malformed frame; caller decides whether to
 *                      reset the connection or escalate
 */
static stm_status process_frame(stm_corvus_notify_consumer *c,
                                  const uint8_t *frame, size_t frame_len)
{
    uint8_t      kind     = 0u;
    const char  *user     = NULL;
    size_t       user_len = 0u;
    stm_status   pr = stm_corvus_notify_parse_frame(frame, frame_len,
                                                       &kind, &user, &user_len);
    if (pr != STM_OK) {
        log_event(c, "stratumd: corvus notify: malformed frame (rc=%d)",
                  (int)pr);
        return pr;
    }
    if (kind != STM_CORVUS_NOTIFY_SESSION_CLOSED) {
        /* Forward-compat: unknown kind logged + ignored. */
        log_event(c, "stratumd: corvus notify: unknown kind %u (ignored)",
                  (unsigned)kind);
        return STM_OK;
    }

    /* SESSION_CLOSED. If a corvus_user filter is set, only fire on
     * exact match (length AND bytes). If unset, every SESSION_CLOSED
     * triggers stop (this branch is for tests; production stratumd
     * always sets corvus_user). */
    bool match;
    if (c->corvus_user_len > 0u) {
        match = (user_len == c->corvus_user_len) &&
                (memcmp(user, c->corvus_user, user_len) == 0);
    } else {
        match = true;
    }

    /* User-name truncated for audit log (R94 P2-2 confidentiality —
     * usernames aren't sensitive but bounding the log line is a
     * defensive habit. We log up to 16 bytes; >16 → "...". */
    char user_safe[20];
    size_t copy_len = user_len <= 16u ? user_len : 16u;
    memcpy(user_safe, user, copy_len);
    if (user_len > 16u) {
        user_safe[copy_len + 0] = '.';
        user_safe[copy_len + 1] = '.';
        user_safe[copy_len + 2] = '.';
        user_safe[copy_len + 3] = '\0';
    } else {
        user_safe[copy_len] = '\0';
    }

    if (match) {
        log_event(c,
            "stratumd: corvus notify: SESSION_CLOSED user='%s' → "
            "triggering clean shutdown", user_safe);
        signal_stop(c);
        return STM_OK;
    }

    log_event(c,
        "stratumd: corvus notify: SESSION_CLOSED user='%s' "
        "(no match for this stratumd) ignored", user_safe);
    return STM_OK;
}

/* Read one notify frame off `fd`. Returns:
 *   STM_OK          → frame consumed (caller may inspect stop_flag)
 *   STM_EPROTOCOL   → wire-format violation; caller MAY tear down
 *                     the connection
 *   STM_EBACKEND    → I/O error
 *   STM_EAGAIN     → EOF (caller decides reconnect vs escalate)
 *   (and stop_flag observed → caller's outer loop exits)
 */
static stm_status read_one_frame(stm_corvus_notify_consumer *c, int fd)
{
    /* Frame: 1 byte kind + 2 bytes LE payload_len, then payload_len
     * body bytes. Bound the body at STM_CORVUS_NOTIFY_PAYLOAD_MAX so
     * a hostile / corrupt sender can't make us allocate or stall on
     * a multi-MB read. */
    uint8_t hdr[STM_CORVUS_NOTIFY_HDR_LEN];
    int rrc = read_full(fd, hdr, sizeof hdr, c);
    if (rrc == 1)  return STM_EAGAIN;            /* clean EOF */
    if (rrc == -1) return STM_OK;                /* stop signaled */
    if (rrc != 0)  return STM_EBACKEND;

    uint16_t payload_len = (uint16_t)((uint16_t)hdr[1] |
                                          ((uint16_t)hdr[2] << 8));
    if (payload_len > STM_CORVUS_NOTIFY_PAYLOAD_MAX)
        return STM_EPROTOCOL;

    /* Build a single contiguous buffer for parse_frame. */
    uint8_t frame[STM_CORVUS_NOTIFY_FRAME_MAX];
    memcpy(frame, hdr, sizeof hdr);
    if (payload_len > 0u) {
        rrc = read_full(fd, frame + STM_CORVUS_NOTIFY_HDR_LEN,
                            payload_len, c);
        if (rrc == 1 || rrc == -2) return STM_EPROTOCOL; /* truncated */
        if (rrc == -1)             return STM_OK;        /* stop */
        if (rrc != 0)              return STM_EBACKEND;
    }

    return process_frame(c, frame,
                            STM_CORVUS_NOTIFY_HDR_LEN + payload_len);
}

/* Top-level consumer loop. Returns when stop_flag is observed OR
 * an unrecoverable error happens (strict-mode EOF; tolerant-mode
 * timeout expiry; fatal connect error).
 *
 * Eviction-ordering invariant: this thread NEVER initiates the
 * unmount itself. On SESSION_CLOSED match it only sets stop_flag.
 * The daemon's main thread observes stop_flag, drains accept loops,
 * tears down /ctl/, scrub, fs (in that order — fs_unmount last,
 * which fires the per-dataset DEK zero). This composes against
 * `v2/specs/eviction.tla`. */
static stm_status consumer_loop(stm_corvus_notify_consumer *c)
{
    /* Initial connect with a budget bounded by tolerant timeout —
     * if corvus is unreachable for `notify_timeout_ms`, the consumer
     * declares ECORVUSGONE + sets stop_flag (the strict-mode posture
     * for the initial-connect class). Strict mode shortens the
     * budget to one attempt. */
    uint32_t budget = c->timeout_ms;
    if (c->mode == STM_CORVUS_NOTIFY_STRICT) {
        /* Single-attempt budget; if corvus isn't there yet we fail. */
        budget = 1u;
    }

    log_event(c, "stratumd: corvus notify: consumer starting (path=%s, mode=%s)",
              c->socket_path,
              c->mode == STM_CORVUS_NOTIFY_STRICT ? "strict" : "tolerant");

    int fd = open_with_retry(c, budget);
    if (fd == -1) {
        /* stop_flag observed before connect succeeded; benign exit. */
        return STM_OK;
    }
    if (fd == -2 || fd < 0) {
        log_event(c, "stratumd: corvus notify: initial connect failed → ECORVUSGONE");
        signal_stop(c);
        return STM_ECORVUSGONE;
    }

    log_event(c, "stratumd: corvus notify: connected");

    while (!stop_observed(c)) {
        stm_status frc = read_one_frame(c, fd);
        if (stop_observed(c)) break;

        if (frc == STM_OK) {
            continue;
        }
        if (frc == STM_EAGAIN) {
            /* EOF. Tolerant: try to reconnect within timeout. */
            close(fd);
            fd = -1;
            log_event(c, "stratumd: corvus notify: EOF received");
            if (c->mode == STM_CORVUS_NOTIFY_STRICT) {
                log_event(c, "stratumd: corvus notify: strict mode → "
                              "triggering shutdown");
                signal_stop(c);
                return STM_ECORVUSGONE;
            }
            int newfd = open_with_retry(c, c->timeout_ms);
            if (newfd == -1) break; /* stop observed during retry */
            if (newfd == -2 || newfd < 0) {
                log_event(c, "stratumd: corvus notify: reconnect "
                              "timed out → ECORVUSGONE");
                signal_stop(c);
                return STM_ECORVUSGONE;
            }
            fd = newfd;
            log_event(c, "stratumd: corvus notify: reconnected");
            continue;
        }
        /* STM_EPROTOCOL / STM_EBACKEND: tear down the connection.
         * Strict: escalate. Tolerant: try to reconnect. */
        log_event(c, "stratumd: corvus notify: frame error rc=%d", (int)frc);
        close(fd);
        fd = -1;
        if (c->mode == STM_CORVUS_NOTIFY_STRICT) {
            signal_stop(c);
            return STM_ECORVUSGONE;
        }
        int newfd = open_with_retry(c, c->timeout_ms);
        if (newfd == -1) break;
        if (newfd == -2 || newfd < 0) {
            signal_stop(c);
            return STM_ECORVUSGONE;
        }
        fd = newfd;
    }

    if (fd >= 0) close(fd);
    log_event(c, "stratumd: corvus notify: consumer exiting cleanly");
    return STM_OK;
}

static void *consumer_main(void *arg)
{
    /* R113 P1-1 doctrine carry: block fatal signals on the consumer
     * thread so SIGINT/SIGTERM/SIGHUP/SIGQUIT route to the main
     * thread (whose signal handler sets stop_flag → all accept
     * loops + this consumer all unblock + exit). */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGQUIT);
    (void)pthread_sigmask(SIG_BLOCK, &block, NULL);

    stm_corvus_notify_consumer *c = (stm_corvus_notify_consumer *)arg;
    c->rc = consumer_loop(c);
    return NULL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public start/stop.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

static char *dupstr_bounded(const char *s, size_t max)
{
    if (!s) return NULL;
    size_t n = 0;
    while (n < max && s[n] != '\0') n++;
    if (n >= max) return NULL; /* refuse oversize */
    char *p = malloc(n + 1u);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

stm_status stm_corvus_notify_start(const stm_corvus_notify_opts *opts,
                                       stm_corvus_notify_consumer **out)
{
    if (!opts || !out) return STM_EINVAL;
    if (!opts->socket_path || !*opts->socket_path) return STM_EINVAL;
    if (!opts->stop_flag) return STM_EINVAL;

    /* Bound the corvus_user length. Empty means "no filter" (every
     * SESSION_CLOSED triggers shutdown — tests + the single-user
     * deployment shape). */
    size_t user_len = 0u;
    if (opts->corvus_user) {
        while (user_len <= STM_CORVUS_USER_MAX &&
                  opts->corvus_user[user_len] != '\0')
            user_len++;
        if (user_len > STM_CORVUS_USER_MAX) return STM_EINVAL;
        /* Sanitize: refuse control bytes. Same posture as parse. */
        for (size_t i = 0; i < user_len; i++) {
            uint8_t b = (uint8_t)opts->corvus_user[i];
            if (b < 0x20u || b == 0x7Fu) return STM_EINVAL;
        }
    }

    stm_corvus_notify_consumer *c = calloc(1, sizeof *c);
    if (!c) return STM_ENOMEM;

    c->socket_path = dupstr_bounded(opts->socket_path,
                                       sizeof((struct sockaddr_un *)0)->sun_path);
    if (!c->socket_path) {
        free(c);
        return STM_EINVAL;
    }
    if (user_len > 0u) {
        c->corvus_user = malloc(user_len + 1u);
        if (!c->corvus_user) {
            free(c->socket_path);
            free(c);
            return STM_ENOMEM;
        }
        memcpy(c->corvus_user, opts->corvus_user, user_len);
        c->corvus_user[user_len] = '\0';
        c->corvus_user_len       = user_len;
    }
    c->mode       = opts->mode;
    c->timeout_ms = opts->notify_timeout_ms > 0u ? opts->notify_timeout_ms
                                                  : CORVUS_DEFAULT_TIMEOUT_MS;
    c->stop_flag  = opts->stop_flag;
    c->ctl        = opts->ctl;
    c->rc         = STM_OK;

    atomic_store_explicit(&c->started, false, memory_order_relaxed);

    int prc = pthread_create(&c->tid, NULL, consumer_main, c);
    if (prc != 0) {
        free(c->socket_path);
        free(c->corvus_user);
        free(c);
        return STM_EIO;
    }
    atomic_store_explicit(&c->started, true, memory_order_release);

    *out = c;
    return STM_OK;
}

stm_status stm_corvus_notify_stop(stm_corvus_notify_consumer *c)
{
    if (!c) return STM_OK;
    if (atomic_load_explicit(&c->started, memory_order_acquire)) {
        /* Signal stop via the caller-provided flag (idempotent). */
        if (c->stop_flag)
            atomic_store_explicit(c->stop_flag, true, memory_order_release);
        (void)pthread_join(c->tid, NULL);
    }
    stm_status rc = c->rc;
    free(c->socket_path);
    free(c->corvus_user);
    free(c);
    return rc;
}
