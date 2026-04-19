/* SPDX-License-Identifier: ISC */
/*
 * stm_testlib — minimal unit-test harness.
 *
 * Usage:
 *     STM_TEST(addition) {
 *         STM_ASSERT_EQ(2 + 2, 4);
 *     }
 *
 *     STM_TEST_MAIN("suite name")
 *
 * Conventions:
 *   - Each STM_TEST(name) registers a test function.
 *   - STM_ASSERT_* macros log and mark current test as failed.
 *   - Test continues after assert failures (soft-assert) so that a single
 *     run surfaces as many broken invariants as possible.
 *   - Exit status: 0 if all pass, 1 otherwise.
 */
#ifndef STRATUM_V2_TEST_HARNESS_H
#define STRATUM_V2_TEST_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*stm_test_fn)(void);

/* Field names are intentionally unusual to avoid clashing with the test name
 * argument passed through STM_TEST(name) via the preprocessor — `name` as a
 * field designator would otherwise be token-substituted. */
typedef struct stm_test_entry {
    const char            *t_label;
    stm_test_fn            t_func;
    struct stm_test_entry *t_next;
} stm_test_entry;

/* Registration via constructor attribute. */
void stm_test_register(stm_test_entry *e);

/* Assertion counters — per-test + suite totals. */
void stm_test_fail  (const char *file, int line, const char *fmt, ...);
void stm_test_info  (const char *fmt, ...);
int  stm_test_run_all(const char *suite_name);

/* Current-test failure signal (checked in the harness). */
extern _Thread_local int stm_test_current_failed;

#define STM_TEST(name_)                                                          \
    static void stm_test_##name_(void);                                          \
    static stm_test_entry stm_test_entry_##name_ = {                             \
        .t_label = #name_, .t_func = stm_test_##name_, .t_next = NULL            \
    };                                                                           \
    __attribute__((constructor)) static void stm_test_ctor_##name_(void) {       \
        stm_test_register(&stm_test_entry_##name_);                              \
    }                                                                            \
    static void stm_test_##name_(void)

#define STM_TEST_MAIN(suite_name)                                                \
    int main(void) { return stm_test_run_all(suite_name); }

/* ------------------------------------------------------------------------- */
/* Assertion macros.                                                          */
/* ------------------------------------------------------------------------- */

#define STM_ASSERT(cond) do {                                                    \
    if (!(cond)) {                                                               \
        stm_test_fail(__FILE__, __LINE__, "assertion failed: %s", #cond);        \
    }                                                                            \
} while (0)

#define STM_ASSERT_EQ(a, b) do {                                                 \
    long long __a = (long long)(a);                                              \
    long long __b = (long long)(b);                                              \
    if (__a != __b) {                                                            \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "expected %s == %s, got %lld vs %lld",                     \
                      #a, #b, __a, __b);                                         \
    }                                                                            \
} while (0)

#define STM_ASSERT_NE(a, b) do {                                                 \
    long long __a = (long long)(a);                                              \
    long long __b = (long long)(b);                                              \
    if (__a == __b) {                                                            \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "expected %s != %s, both were %lld",                       \
                      #a, #b, __a);                                              \
    }                                                                            \
} while (0)

#define STM_ASSERT_TRUE(cond)   STM_ASSERT(!!(cond))
#define STM_ASSERT_FALSE(cond)  STM_ASSERT(!(cond))

#define STM_ASSERT_OK(expr) do {                                                 \
    int __s = (int)(expr);                                                       \
    if (__s != 0) {                                                              \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "expected STM_OK, got %d (%s)", __s,                       \
                      stm_strerror((stm_status)__s));                            \
    }                                                                            \
} while (0)

#define STM_ASSERT_ERR(expr, expected_status) do {                               \
    int __s = (int)(expr);                                                       \
    int __e = (int)(expected_status);                                            \
    if (__s != __e) {                                                            \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "expected %d (%s), got %d (%s)",                           \
                      __e, stm_strerror((stm_status)__e),                        \
                      __s, stm_strerror((stm_status)__s));                       \
    }                                                                            \
} while (0)

#define STM_ASSERT_MEM_EQ(a, b, n) do {                                          \
    if (memcmp((a), (b), (n)) != 0) {                                            \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "memory mismatch of %zu bytes (%s vs %s)",                 \
                      (size_t)(n), #a, #b);                                      \
    }                                                                            \
} while (0)

#define STM_ASSERT_MEM_NE(a, b, n) do {                                          \
    if (memcmp((a), (b), (n)) == 0) {                                            \
        stm_test_fail(__FILE__, __LINE__,                                        \
                      "expected memory to differ (%s vs %s, %zu bytes)",         \
                      #a, #b, (size_t)(n));                                      \
    }                                                                            \
} while (0)

/* ------------------------------------------------------------------------- */
/* Property-based helpers.                                                    */
/* ------------------------------------------------------------------------- */

/* Deterministic PRNG (splitmix64). Seeded per test via STM_PROP_SEED. */
uint64_t stm_prop_rand     (void);
void     stm_prop_seed     (uint64_t seed);
void     stm_prop_fill     (void *buf, size_t n);
uint32_t stm_prop_rand_u32_below(uint32_t bound);

#ifdef __cplusplus
}
#endif
#endif
