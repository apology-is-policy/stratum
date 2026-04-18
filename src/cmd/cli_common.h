#ifndef STM_CLI_COMMON_H
#define STM_CLI_COMMON_H

/*
 * Shared helpers for the stratum CLI subcommands (stratum.c, check.c,
 * scrub.c). Consolidating here avoids divergent local reimplementations
 * — the earlier fgets/strlen-based passphrase readers silently truncated
 * on NUL, passed through `\r` from CRLF-terminated pipes, and silently
 * dropped overlength input. The canonical reader below rejects all three
 * cases with a clear error message.
 */

/* Read a single passphrase line from stdin, byte-by-byte. Strips a
 * trailing '\r' so CRLF-terminated input from Windows pipes matches LF
 * input. Returns NULL on EOF, empty input, embedded NUL, or overlength
 * (>255 bytes) — with a stderr message for the NUL / overlength cases.
 * The returned pointer is to a static buffer; valid until the next call. */
const char *stm_cli_read_pass_stdin(void);

#endif /* STM_CLI_COMMON_H */
