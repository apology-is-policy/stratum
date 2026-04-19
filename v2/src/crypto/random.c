/* SPDX-License-Identifier: ISC */
#include <stratum/crypto.h>
#include <sodium.h>

void stm_random_bytes(void *out, size_t n)
{
    randombytes_buf(out, n);
}
