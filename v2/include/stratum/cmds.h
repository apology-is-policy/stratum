/* SPDX-License-Identifier: ISC */
/*
 * Command-line entry points for the four stratum cmd-line tools.
 *
 * These are the same functions that each tool's standalone `main()`
 * delegates to. Exposing them as public symbols lets the swiss-army
 * `stratum` Rust binary (v2/tools/stratum/) dispatch subcommands
 * by FFI-calling the right entry point — same code path, no fork/exec.
 *
 * Each function:
 *   - Parses argv as the corresponding standalone tool would.
 *   - Installs SIGINT/SIGTERM handlers (the daemon variants only).
 *   - Returns the exit code the tool would exit with.
 *
 * Thread-safety: each entry point uses file-scope state (stop flags,
 * signal-handler registrations). Calling two of them concurrently in
 * the same process is undefined. The swiss-army binary's embedded
 * mode (v2/tools/stratum/src/embed.rs) calls each on its own pthread
 * AT MOST ONCE per process lifetime — process-wide globals are fine
 * under that contract.
 *
 * The argv passed to these entry points has the tool's name as
 * argv[0] (e.g. argv[0]="stratumd"); subcommand routing in the
 * Rust dispatcher reconstructs argv such that tool-internal usage
 * messages remain consistent with the standalone binaries.
 */
#ifndef STRATUM_V2_CMDS_H
#define STRATUM_V2_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

int stm_cmd_stratumd_main(int argc, char **argv);
int stm_cmd_slate_main   (int argc, char **argv);
int stm_cmd_mkfs_main    (int argc, char **argv);
int stm_cmd_fs_main      (int argc, char **argv);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CMDS_H */
