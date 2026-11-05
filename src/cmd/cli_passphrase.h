/* SPDX-License-Identifier: ISC */
/*
 * SWISS-4m: shared passphrase-reader for stratum-mkfs / stratumd.
 *
 * Reads a single line from stdin (up to STM_CLI_PASSPHRASE_MAX bytes)
 * into the caller's buffer. Strips a trailing '\n' if present.
 * Returns the byte count via *out_len; the buffer is NOT NUL-terminated
 * (passphrases are opaque bytes — embedded NULs would be silently
 * truncated by string semantics, so we treat the buffer as a span).
 *
 * Error cases (returns negative stm_status):
 *   - STM_EINVAL: NULL args
 *   - STM_ERANGE: line exceeds STM_CLI_PASSPHRASE_MAX
 *   - STM_EBACKEND: read error (rare; stdin closed mid-line is OK
 *     and yields whatever was read so far)
 *
 * Memory hygiene: caller is responsible for calling stm_ct_memzero
 * on the buffer after the passphrase is no longer needed (i.e., after
 * KDF derivation).
 *
 * mlock is ATTEMPTED on the caller's buffer (best-effort; failures
 * are logged once to stderr and ignored — mlock requires elevated
 * privileges on most systems).
 */
#ifndef STRATUM_V2_CLI_PASSPHRASE_H
#define STRATUM_V2_CLI_PASSPHRASE_H

#include <stratum/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STM_CLI_PASSPHRASE_MAX  255u

STM_MUST_USE
stm_status stm_cli_read_passphrase_stdin(char  *buf,
                                            size_t buf_cap,
                                            size_t *out_len);

/* Best-effort mlock + memzero helper. mlock failure is silent. */
void stm_cli_passphrase_lock_best_effort(void *buf, size_t len);
void stm_cli_passphrase_unlock(void *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CLI_PASSPHRASE_H */
