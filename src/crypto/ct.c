/* SPDX-License-Identifier: ISC */
#include <stratum/crypto.h>
#include <sodium.h>

bool stm_ct_equal(const void *a, const void *b, size_t n)
{
    return sodium_memcmp(a, b, n) == 0;
}

void stm_ct_memzero(void *p, size_t n)
{
    sodium_memzero(p, n);
}
