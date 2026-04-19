/* SPDX-License-Identifier: ISC */
/*
 * X25519 via libsodium's crypto_scalarmult_*.
 */
#include <stratum/crypto.h>

#include <sodium.h>

void stm_x25519_keygen(uint8_t pk[STM_X25519_PK_LEN],
                       uint8_t sk[STM_X25519_SK_LEN])
{
    /*
     * Per RFC 7748 X25519: secret scalar must have bits 0..2 cleared, bit 254
     * set, bit 255 cleared. libsodium's `crypto_scalarmult_base` applies the
     * clamping internally, but generating a random sk then calling base is
     * the idiomatic keygen.
     */
    randombytes_buf(sk, STM_X25519_SK_LEN);
    (void)crypto_scalarmult_base(pk, sk);
}

stm_status stm_x25519_dh(const uint8_t sk[STM_X25519_SK_LEN],
                         const uint8_t pk[STM_X25519_PK_LEN],
                         uint8_t ss[STM_X25519_SS_LEN])
{
    /*
     * `crypto_scalarmult` returns -1 for "all-zero shared secret" (edge-case
     * low-order point). Treat as protocol violation: the peer sent a
     * degenerate public key.
     */
    int r = crypto_scalarmult(ss, sk, pk);
    if (r != 0) return STM_EPROTOCOL;
    return STM_OK;
}
