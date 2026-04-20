/* SPDX-License-Identifier: ISC */
/*
 * ML-KEM-768 via liboqs.
 *
 * When STM_HAVE_LIBOQS=0, all ML-KEM entry points return STM_ENOTSUPPORTED.
 * This lets the rest of the codebase link and run for environments without
 * liboqs, at the cost of the PQ wrap falling back to X25519-only.
 *
 * Implementation note: we use the generic `OQS_KEM_new(OQS_KEM_alg_ml_kem_768)`
 * API rather than the direct `OQS_KEM_ml_kem_768_*` symbols. The direct
 * symbols have been through naming churn (_ipd_ suffix in 0.10.x, renamed
 * in 0.11.x, sometimes present only in one form per release), so the
 * generic dispatch path is the most portable across versions. The extra
 * alloc/free per operation is negligible at the call frequencies the wrap
 * layer exercises (once per key wrap, not per message).
 */
#include <stratum/crypto.h>

#if STM_HAVE_LIBOQS
#include <oqs/oqs.h>
#include <string.h>

/* FIPS 203 ML-KEM-768 constants. Assert at compile time against liboqs. */
STM_STATIC_ASSERT(STM_MLKEM768_PK_LEN == OQS_KEM_ml_kem_768_length_public_key,
                  "ML-KEM-768 pk len mismatch");
STM_STATIC_ASSERT(STM_MLKEM768_SK_LEN == OQS_KEM_ml_kem_768_length_secret_key,
                  "ML-KEM-768 sk len mismatch");
STM_STATIC_ASSERT(STM_MLKEM768_CT_LEN == OQS_KEM_ml_kem_768_length_ciphertext,
                  "ML-KEM-768 ct len mismatch");
STM_STATIC_ASSERT(STM_MLKEM768_SS_LEN == OQS_KEM_ml_kem_768_length_shared_secret,
                  "ML-KEM-768 ss len mismatch");

bool stm_mlkem768_available(void) { return true; }

stm_status stm_mlkem768_keygen(uint8_t pk[STM_MLKEM768_PK_LEN],
                               uint8_t sk[STM_MLKEM768_SK_LEN])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return STM_EBACKEND;
    OQS_STATUS r = OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    return (r == OQS_SUCCESS) ? STM_OK : STM_EBACKEND;
}

stm_status stm_mlkem768_encap(const uint8_t pk[STM_MLKEM768_PK_LEN],
                              uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return STM_EBACKEND;
    OQS_STATUS r = OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_free(kem);
    return (r == OQS_SUCCESS) ? STM_OK : STM_EBACKEND;
}

stm_status stm_mlkem768_decap(const uint8_t sk[STM_MLKEM768_SK_LEN],
                              const uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return STM_EBACKEND;
    OQS_STATUS r = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_KEM_free(kem);
    return (r == OQS_SUCCESS) ? STM_OK : STM_EBACKEND;
}

#else  /* !STM_HAVE_LIBOQS */

bool stm_mlkem768_available(void) { return false; }

stm_status stm_mlkem768_keygen(uint8_t pk[STM_MLKEM768_PK_LEN],
                               uint8_t sk[STM_MLKEM768_SK_LEN])
{
    (void)pk; (void)sk;
    return STM_ENOTSUPPORTED;
}

stm_status stm_mlkem768_encap(const uint8_t pk[STM_MLKEM768_PK_LEN],
                              uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN])
{
    (void)pk; (void)ct; (void)ss;
    return STM_ENOTSUPPORTED;
}

stm_status stm_mlkem768_decap(const uint8_t sk[STM_MLKEM768_SK_LEN],
                              const uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN])
{
    (void)sk; (void)ct; (void)ss;
    return STM_ENOTSUPPORTED;
}

#endif
