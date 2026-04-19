/* SPDX-License-Identifier: ISC */
#include <stratum/crypto.h>
#include <sodium.h>

stm_status stm_crypto_init(void)
{
    int r = sodium_init();
    if (r < 0) return STM_EBACKEND;
    /* r == 1 means already initialized; treat as success. */
    return STM_OK;
}
