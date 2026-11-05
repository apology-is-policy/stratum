/* SPDX-License-Identifier: ISC */
/*
 * host_fs — POSIX directory tree exported as 9P2000.L, read-only.
 *
 * SWISS-2: gives the swiss-army `stratum` binary the ability to
 * mount a host filesystem path as the source side of a copy
 * operation. The TUI's Shift+F2 verb (FAR Commander idiom for
 * "mount host filesystem to inactive panel") spawns a host_fs
 * server and attaches it to slate's right panel.
 *
 * Read-only at v1.0 (paranoid default — the TUI shouldn't `rm -rf`
 * a host home dir by accident). Twrite, Tlcreate, Tmkdir, Tunlinkat,
 * Tsetattr, Tsymlink return Rlerror(EROFS); only walk / lopen-RDONLY
 * / read / readdir / getattr / readlink / clunk succeed.
 *
 * Trust boundaries:
 *   1. **Root containment**: every Twalk component is rejected if it
 *      contains '/' or equals "..". The lp9 server already strips
 *      '/' from names; we add the ".." check. After walk, the
 *      resulting absolute path is verified to start with the root
 *      prefix (defense-in-depth against symlinks pointing outside
 *      the root).
 *
 *   2. **Symlink resolution policy**: walk follows symlinks by
 *      default (matches POSIX path resolution semantics). The
 *      root-prefix check at the end of walk catches symlinks that
 *      escape the root. Symlinks themselves are reported as
 *      qid type LP9_QTSYMLINK; Treadlink returns the link target.
 *
 *   3. **Caller-cap on every server-supplied count** (R111 doctrine
 *      carry): pread() and getdents() return values are bounded by
 *      the caller's count parameter; readlink() output is bounded
 *      by the caller's buf_cap.
 *
 *   4. **Per-fid state lifecycle**: each fid that walks to a path
 *      gets a host_fs_fid entry holding the absolute host path +
 *      optional open fd (file) or DIR* (dir). Tclunk frees both.
 *      The fd / DIR* close BEFORE the path string frees so a
 *      late-arriving syscall on a closed fd doesn't reach into
 *      freed memory.
 *
 *   5. **NUL in path**: paths are always NUL-terminated host strings.
 *      Walk components arrive with explicit length; we copy into
 *      a NUL-terminated buffer (R123 doctrine carry — never let a
 *      length-prefixed input flow into a NUL-terminated POSIX API).
 *
 *   6. **Concurrency**: one stm_host_fs instance per lp9 server
 *      connection. Each server is single-threaded per connection
 *      (lp9.h doctrine), so the per-fid table doesn't need locking.
 *      For concurrent-accept upgrades, fanout is the caller's
 *      problem (each accept spawns a fresh host_fs instance).
 */
#ifndef STRATUM_V2_HOST_FS_H
#define STRATUM_V2_HOST_FS_H

#include <stratum/lp9.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stm_host_fs stm_host_fs;

/*
 * Create a host_fs instance rooted at `root_path` (an absolute host
 * path that must exist and be a directory). Returns STM_OK on
 * success; STM_EINVAL on NULL/relative/non-existent path; STM_ENOMEM
 * on alloc failure; STM_ENOTDIR if path is not a directory.
 */
STM_MUST_USE
stm_status stm_host_fs_create(const char *root_path, stm_host_fs **out);

/*
 * Destroy. Closes every per-fid fd / DIR*. Safe on NULL.
 */
void stm_host_fs_destroy(stm_host_fs *h);

/*
 * vops table. Static lifetime — caller does not free.
 */
const stm_lp9_vops *stm_host_fs_vops(void);

/*
 * Root qid_path to pass to stm_lp9_server_create. Identical for
 * every host_fs instance; the qid layout encodes inode-derived
 * identity, not the instance pointer.
 */
uint64_t stm_host_fs_root(const stm_host_fs *h);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_HOST_FS_H */
