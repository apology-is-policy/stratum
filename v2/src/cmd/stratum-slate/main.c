/* SPDX-License-Identifier: ISC */
/* stratum-slate standalone binary — thin wrapper over stm_cmd_slate_main.
 *
 * The substantive lifecycle (argv parsing, accept loop, worker pool,
 * signal handlers) lives in run.c so the swiss-army `stratum` Rust
 * binary can FFI-dispatch into the same code path.
 */
#include <stratum/cmds.h>

int main(int argc, char **argv)
{
    return stm_cmd_slate_main(argc, argv);
}
