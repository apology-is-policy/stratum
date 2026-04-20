/* SPDX-License-Identifier: ISC */
/*
 * Argon2id via libsodium's crypto_pwhash. Passphrase → wrap-key derivation.
 *
 * libsodium exposes tuning as (opslimit, memlimit) pairs; we map our
 * (t_cost, m_cost_kib) struct onto them. Parallelism is fixed to 1 by
 * libsodium's Argon2 binding; we expose it in the struct for documentation
 * only.
 */
#include <stratum/crypto.h>

#include <sodium.h>
#include <string.h>

stm_argon2id_params stm_argon2id_params_interactive(const uint8_t salt[16])
{
    stm_argon2id_params p = {
        /* libsodium's INTERACTIVE: 2 ops, 64 MiB. ~100-150 ms on a 2020 laptop. */
        .t_cost      = 2,
        .m_cost_kib  = 65536,
        .parallelism = 1,
    };
    memcpy(p.salt, salt, 16);
    return p;
}

stm_argon2id_params stm_argon2id_params_sensitive(const uint8_t salt[16])
{
    stm_argon2id_params p = {
        /* libsodium's SENSITIVE: 4 ops, 1 GiB. ~2-4 s on the same hardware. */
        .t_cost      = 4,
        .m_cost_kib  = 1048576,
        .parallelism = 1,
    };
    memcpy(p.salt, salt, 16);
    return p;
}

stm_status stm_argon2id(const stm_argon2id_params *p,
                        const char *passphrase, size_t pass_len,
                        uint8_t *out, size_t out_len)
{
    if (!p || !passphrase || !out) return STM_EINVAL;
    if (out_len < crypto_pwhash_BYTES_MIN || out_len > crypto_pwhash_BYTES_MAX)
        return STM_ERANGE;
    /* crypto_pwhash_PASSWD_MIN is 0 on current libsodium, so `pass_len <
     * MIN` is vacuous for our size_t argument and -Wtype-limits rightly
     * flags it. We still guard the upper bound. */
    if (pass_len > crypto_pwhash_PASSWD_MAX) return STM_ERANGE;

    /* libsodium memlimit is bytes. */
    size_t memlimit = p->m_cost_kib * 1024ull;
    unsigned long long opslimit = p->t_cost;

    int r = crypto_pwhash(out, out_len,
                          passphrase, pass_len,
                          p->salt,
                          opslimit, memlimit,
                          crypto_pwhash_ALG_ARGON2ID13);
    if (r != 0) return STM_EBACKEND;
    return STM_OK;
}
