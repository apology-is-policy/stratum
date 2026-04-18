#include "cli_common.h"

#include <stdio.h>
#include <stddef.h>

static char stdin_pass_buf[256];

const char *stm_cli_read_pass_stdin(void)
{
    size_t len = 0;
    for (;;) {
        int c = getchar();
        if (c == EOF || c == '\n') break;
        if (c == '\0') {
            fprintf(stderr, "Passphrase contains a NUL byte — rejected "
                            "(would be silently truncated otherwise).\n");
            return NULL;
        }
        if (c == '\r') continue;
        if (len + 1 >= sizeof(stdin_pass_buf)) {
            fprintf(stderr, "Passphrase too long (max %zu bytes).\n",
                    sizeof(stdin_pass_buf) - 1);
            return NULL;
        }
        stdin_pass_buf[len++] = (char)c;
    }
    stdin_pass_buf[len] = '\0';
    return len > 0 ? stdin_pass_buf : NULL;
}
