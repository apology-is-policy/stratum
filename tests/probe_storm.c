/* A PROBE, never to be merged: what a storm of signals looks like on this machine.
 *
 * probe_storm MODE SENDERS SECONDS
 *
 * The main thread waits in poll() on a pipe nobody writes, 20 ms at a time, as the 9P
 * client does. SENDERS threads each send it SIGUSR1, then wait 0.2 ms by MODE: sleep
 * (nanosleep), yield (the clock, sched_yield between looks) or spin (the clock alone).
 * Printed: the gaps between one signal and the next, all senders together; the waits as
 * they came, and the whole milliseconds a count floored to milliseconds would make of them
 * in the first half; how long each pthread_kill and each pause took; the context switches. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define EVERY_NS 200000u
#define NB 9

static const uint64_t edge_us[NB - 1] = { 250, 500, 1000, 2000, 5000, 10000, 20000, 50000 };
static const char *const edge_name[NB] = { "<0.25", "<0.5", "<1", "<2", "<5", "<10", "<20", "<50", ">=50" };

enum { SLEEP, YIELD, SPIN };

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static int bucket(uint64_t ns)
{
    uint64_t us = ns / 1000u;
    int b = 0;
    while (b < NB - 1 && us >= edge_us[b]) b++;
    return b;
}

static void show(const char *what, const unsigned *h)
{
    printf("  %s:", what);
    for (int i = 0; i < NB; i++) printf(" %s=%u", edge_name[i], h[i]);
    printf("\n");
}

typedef struct {
    pthread_t whom;
    int       mode;
    uint64_t  until;
    uint64_t *at;
    size_t    cap, n;
    uint64_t  kill_sum, kill_max, pause_max;
    unsigned  pause_h[NB];
} sender;

static atomic_bool stop_sending;

static void *send_loop(void *arg)
{
    sender *s = arg;
    struct timespec pause = { 0, EVERY_NS };
    while (!atomic_load(&stop_sending)) {
        uint64_t t0 = now_ns();
        if (t0 >= s->until) break;
        pthread_kill(s->whom, SIGUSR1);
        uint64_t t1 = now_ns();
        if (s->n < s->cap) s->at[s->n++] = t1;
        uint64_t k = t1 - t0;
        s->kill_sum += k;
        if (k > s->kill_max) s->kill_max = k;
        uint64_t next = t1 + EVERY_NS;
        if (s->mode == SLEEP) nanosleep(&pause, NULL);
        else if (s->mode == YIELD) while (now_ns() < next) sched_yield();
        else while (now_ns() < next) {}
        uint64_t p = now_ns() - t1;
        s->pause_h[bucket(p)]++;
        if (p > s->pause_max) s->pause_max = p;
    }
    return NULL;
}

static void nothing(int sig)
{
    (void)sig;
}

static int by_time(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: probe_storm sleep|yield|spin SENDERS SECONDS\n");
        return 2;
    }
    int mode = !strcmp(argv[1], "sleep") ? SLEEP : !strcmp(argv[1], "yield") ? YIELD
             : !strcmp(argv[1], "spin") ? SPIN : -1;
    int senders = atoi(argv[2]), secs = atoi(argv[3]);
    if (mode < 0 || senders < 1 || senders > 8 || secs < 1 || secs > 60) {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = nothing;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) return 2;
    int fds[2];
    if (pipe(fds) != 0) return 2;

    struct rusage ru0, ru1;
    getrusage(RUSAGE_SELF, &ru0);
    uint64_t began = now_ns();
    uint64_t until = began + (uint64_t)secs * 1000000000u;
    uint64_t half = began + (uint64_t)secs * 500000000u;
    sender s[8];
    pthread_t t[8];
    size_t cap = (size_t)secs * (1000000000u / EVERY_NS) + 1000u;
    for (int i = 0; i < senders; i++) {
        memset(&s[i], 0, sizeof s[i]);
        s[i].whom = pthread_self();
        s[i].mode = mode;
        s[i].until = until;
        s[i].cap = cap;
        s[i].at = calloc(cap, sizeof(uint64_t));
        if (!s[i].at) return 2;
    }
    for (int i = 0; i < senders; i++)
        if (pthread_create(&t[i], NULL, send_loop, &s[i]) != 0) return 2;

    unsigned wait_h[NB] = { 0 };
    uint64_t waits = 0, eintr = 0, timeouts = 0, wait_max = 0, wait_sum = 0;
    uint64_t floored = 0, floored_half = 0;
    struct pollfd p = { fds[0], POLLIN, 0 };
    /* PROBE_WAITER=sleep: the main thread sleeps 10 ms at a time instead of polling. */
    const char *wv = getenv("PROBE_WAITER");
    bool sleeper = wv && !strcmp(wv, "sleep");
    for (;;) {
        uint64_t w0 = now_ns();
        if (w0 >= until) break;
        int r, e;
        if (sleeper) {
            struct timespec ten = { 0, 10000000L };
            r = nanosleep(&ten, NULL);
        } else {
            r = poll(&p, 1, 20);
        }
        e = errno;
        uint64_t w = now_ns() - w0;
        waits++;
        if (r < 0 && e == EINTR) eintr++;
        else if (r == 0) timeouts++;
        wait_h[bucket(w)]++;
        wait_sum += w;
        if (w > wait_max) wait_max = w;
        floored += w / 1000000u;
        if (w0 < half) floored_half += w / 1000000u;
    }
    atomic_store(&stop_sending, true);
    for (int i = 0; i < senders; i++) pthread_join(t[i], NULL);
    getrusage(RUSAGE_SELF, &ru1);

    size_t total = 0;
    for (int i = 0; i < senders; i++) total += s[i].n;
    uint64_t *all = malloc((total ? total : 1) * sizeof(uint64_t));
    if (!all) return 2;
    size_t k = 0;
    for (int i = 0; i < senders; i++) {
        memcpy(all + k, s[i].at, s[i].n * sizeof(uint64_t));
        k += s[i].n;
    }
    qsort(all, total, sizeof(uint64_t), by_time);
    unsigned gap_h[NB] = { 0 };
    uint64_t gap_max = 0, gap_floored = 0, gap_floored_half = 0;
    for (size_t j = 1; j < total; j++) {
        uint64_t g = all[j] - all[j - 1];
        gap_h[bucket(g)]++;
        if (g > gap_max) gap_max = g;
        gap_floored += g / 1000000u;
        if (all[j - 1] < half) gap_floored_half += g / 1000000u;
    }

    double cpu = (double)(ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec + ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec)
               + (double)(ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec + ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec) / 1e6;
    printf("PROBE_STORM %s x%d %ds%s, %ld cpus: %zu signals (%.2f a ms), %llu waits (%llu interrupted, %llu timed out)\n",
           argv[1], senders, secs, sleeper ? " (waiter sleeps)" : "", sysconf(_SC_NPROCESSORS_ONLN), total, (double)total / (secs * 1000.0),
           (unsigned long long)waits, (unsigned long long)eintr, (unsigned long long)timeouts);
    show("gaps ", gap_h);
    printf("  gaps : longest %.2f ms; whole ms between them %llu, in the first half %llu (a limit of 300 in 3 s)\n",
           gap_max / 1e6, (unsigned long long)gap_floored, (unsigned long long)gap_floored_half);
    show("waits", wait_h);
    printf("  waits: longest %.2f ms, mean %.3f ms; floored to whole ms %llu, in the first half %llu\n",
           wait_max / 1e6, waits ? wait_sum / 1e6 / (double)waits : 0.0, (unsigned long long)floored,
           (unsigned long long)floored_half);
    for (int i = 0; i < senders; i++) {
        printf("  sender %d: %zu sent; pthread_kill mean %.1f us, longest %.1f us; pause longest %.2f ms;",
               i, s[i].n, s[i].n ? s[i].kill_sum / 1e3 / (double)s[i].n : 0.0, s[i].kill_max / 1e3, s[i].pause_max / 1e6);
        show("pauses", s[i].pause_h);
    }
    printf("  cpu %.2f s in %d s; context switches: %ld voluntary, %ld involuntary\n", cpu, secs,
           ru1.ru_nvcsw - ru0.ru_nvcsw, ru1.ru_nivcsw - ru0.ru_nivcsw);
    for (int i = 0; i < senders; i++) free(s[i].at);
    free(all);
    return 0;
}
