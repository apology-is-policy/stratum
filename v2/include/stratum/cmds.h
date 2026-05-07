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
 * Thread-safety: each entry point owns process-wide file-scope state
 * (stop flags, signal-handler registrations) — calling two of these
 * functions concurrently in the same address space, OR re-calling one
 * after a prior invocation returned, is UNDEFINED.
 *
 * Two correct deployment shapes exist:
 *
 *   1. **Standalone subcommand dispatch** (the SWISS-1 model the
 *      swiss-army `stratum` binary uses): the Rust `stratum` binary
 *      receives a subcommand like `stratum serve VOL ...`, calls the
 *      relevant `stm_cmd_<name>_main` once, and exits when it
 *      returns. Process-wide globals are fine because the process
 *      ends with the call.
 *
 *   2. **Embedded re-exec** (the SWISS-1 `tui --vol` mode): each
 *      daemon runs in its own child process spawned via
 *      `Command::new(current_exe()).args(...)`. The child re-execs
 *      stratum with a different subcommand, which routes to the
 *      relevant `stm_cmd_<name>_main`. Each child has its own
 *      address space + signal-handler table + atomic globals —
 *      no shared state with the parent or sibling children.
 *
 * What is NOT supported (and never will be without an `int with_signals`
 * flag on each entry point):
 *
 *   - Calling `stm_cmd_<name>_main` from a pthread inside a host
 *     process that has its own SIGINT handler. The handlers race
 *     and the host's handler is silently overridden.
 *
 *   - Calling the same entry point twice in one process lifetime.
 *     g_stop_flag stays set after first invocation; second call
 *     short-circuits or wedges depending on the daemon.
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
