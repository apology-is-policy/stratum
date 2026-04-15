#ifndef STM_TEST_MAIN_H
#define STM_TEST_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STM_TEST(name) static void name(void)

#define STM_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define STM_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "  FAIL %s:%d: %s != %s\n", \
                __FILE__, __LINE__, #a, #b); \
        exit(1); \
    } \
} while (0)

#define STM_ASSERT_MEM_EQ(a, b, n) do { \
    if (memcmp((a), (b), (n)) != 0) { \
        fprintf(stderr, "  FAIL %s:%d: memcmp(%s, %s, %s)\n", \
                __FILE__, __LINE__, #a, #b, #n); \
        exit(1); \
    } \
} while (0)

#define STM_RUN(fn) do { \
    printf("  %-50s", #fn); \
    fn(); \
    printf("OK\n"); \
} while (0)

#define STM_SUITE(name) printf("suite: %s\n", name)

#endif /* STM_TEST_MAIN_H */
