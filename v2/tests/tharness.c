/* SPDX-License-Identifier: ISC */
#include "tharness.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static stm_test_entry *g_head;
_Thread_local int stm_test_current_failed;

void stm_test_register(stm_test_entry *e)
{
    /* Prepend; order of construction across TUs is not guaranteed but all
     * tests run regardless. */
    e->t_next = g_head;
    g_head = e;
}

void stm_test_fail(const char *file, int line, const char *fmt, ...)
{
    stm_test_current_failed = 1;
    fprintf(stderr, "  FAIL %s:%d: ", file, line);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void stm_test_info(const char *fmt, ...)
{
    fprintf(stderr, "  info: ");
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

int stm_test_run_all(const char *suite_name)
{
    /* Reverse list to restore declaration order. */
    stm_test_entry *list = NULL;
    for (stm_test_entry *e = g_head; e; ) {
        stm_test_entry *next = e->t_next;
        e->t_next = list;
        list = e;
        e = next;
    }

    int npass = 0, nfail = 0;
    fprintf(stderr, "== %s ==\n", suite_name);
    for (stm_test_entry *e = list; e; e = e->t_next) {
        stm_test_current_failed = 0;
        fprintf(stderr, "RUN   %s\n", e->t_label);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        e->t_func();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                  + (t1.tv_nsec - t0.tv_nsec) / 1e6;
        if (stm_test_current_failed) {
            fprintf(stderr, "FAIL  %s (%.1f ms)\n", e->t_label, ms);
            nfail++;
        } else {
            fprintf(stderr, "ok    %s (%.1f ms)\n", e->t_label, ms);
            npass++;
        }
    }
    fprintf(stderr, "-- %d passed, %d failed\n", npass, nfail);
    return nfail == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------------- */
/* splitmix64 PRNG — deterministic, no state outside the thread.              */
/* ------------------------------------------------------------------------- */

static _Thread_local uint64_t g_prop_state = 0x9E3779B97F4A7C15ull;

void stm_prop_seed(uint64_t seed) { g_prop_state = seed; }

uint64_t stm_prop_rand(void)
{
    uint64_t z = (g_prop_state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

void stm_prop_fill(void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n >= 8) {
        uint64_t v = stm_prop_rand();
        memcpy(p, &v, 8);
        p += 8; n -= 8;
    }
    if (n) {
        uint64_t v = stm_prop_rand();
        memcpy(p, &v, n);
    }
}

uint32_t stm_prop_rand_u32_below(uint32_t bound)
{
    if (bound == 0) return 0;
    return (uint32_t)(stm_prop_rand() % bound);
}
