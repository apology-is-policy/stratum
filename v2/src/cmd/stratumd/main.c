/* SPDX-License-Identifier: ISC */
/* stratumd standalone binary — thin wrapper over stm_cmd_stratumd_main.
 *
 * The substantive lifecycle (argv parsing, signal handlers, run-loop,
 * exit codes) lives in run.c so the swiss-army `stratum` Rust binary
 * can FFI-dispatch into the same code path.
 */
#include <stratum/cmds.h>

int main(int argc, char **argv)
{
    return stm_cmd_stratumd_main(argc, argv);
}
