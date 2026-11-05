/* SPDX-License-Identifier: ISC */
#include "cli_passphrase.h"

#include <stratum/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

stm_status stm_cli_read_passphrase_stdin(char  *buf,
                                            size_t buf_cap,
                                            size_t *out_len)
{
    if (!buf || !out_len || buf_cap == 0) return STM_EINVAL;

    *out_len = 0;
    size_t off = 0;
    while (off < buf_cap) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EBACKEND;
        }
        if (n == 0) break;          /* EOF — return what we have */
        if (c == '\n') break;       /* line terminator */
        buf[off++] = c;
    }
    if (off == buf_cap) {
        /* Caller's buffer is full but no newline reached — they
         * provided too small a buffer for the actual input, OR the
         * input is genuinely too long. Either way refuse. */
        return STM_ERANGE;
    }
    *out_len = off;
    return STM_OK;
}

void stm_cli_passphrase_lock_best_effort(void *buf, size_t len)
{
    if (!buf || len == 0) return;
    /* mlock pins the page so it never gets paged out to swap. On
     * macOS + Linux this requires either CAP_IPC_LOCK or running as
     * root; under normal user privileges it commonly fails with
     * EPERM. We treat that as best-effort. */
    if (mlock(buf, len) != 0) {
        static int warned = 0;
        if (!warned && errno != EPERM) {
            fprintf(stderr,
                "stratum: warning: mlock(passphrase) failed (errno=%d). "
                "Plaintext passphrase may be paged to disk briefly during KDF.\n",
                errno);
            warned = 1;
        }
        /* Don't propagate failure — KDF still safe in-RAM. */
    }
}

void stm_cli_passphrase_unlock(void *buf, size_t len)
{
    if (!buf || len == 0) return;
    (void)munlock(buf, len);
}
