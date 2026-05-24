# Session handoff -- Thylacine pouch arm -- 2026-05-24

Branch **`thylacine-pouch-arm`** off **`main`@`976cb6f`** (the R172 close
tip). **Not pushed; user-pushed.** Authored by the Thylacine session
running on its own working tree (`~/projects/thylacine/`) for **Phase 6
sub-chunk 15 (`pouch-stratumd-build`)** -- cross-compile stratumd
against the pouch sysroot. The Stratum agent was paused during this
work (per the user's coordination preference); this artifact is the
hand-off note describing what changed and why.

## TL;DR

Two files changed on this branch:

| File | Change | Reason |
|---|---|---|
| `CMakeLists.txt` | Adds `STM_PLATFORM_THYLACINE` detection; synthesizes `Threads::Threads` + `PkgConfig::LIBSODIUM` IMPORTED targets on Thylacine; skips `_FORTIFY_SOURCE=2` on Thylacine. | Host `find_package(Threads)` and `pkg_check_modules(libsodium)` don't see the cross-sysroot (pouch's musl bundles pthread in libc; libsodium ships pre-built in the sysroot without a `.pc` file). musl doesn't implement `_FORTIFY_SOURCE`. |
| `src/cmd/stratumd/peer_creds.c` | Extends the `__linux__` arm guard to `__linux__ \|\| __thylacine__`. Same body. | The Thylacine arm in POUCH-DESIGN.md section 10. Pouch's `0006-pouch-sockets.patch` already marshals `getsockopt(SO_PEERCRED)` onto Thylacine's `SYS_srv_peer` underneath, so the Linux arm body works unchanged on Thylacine. |

Stratumd cross-builds clean: 860 KB static ET_EXEC produced at
`<thylacine-tree>/build/pouch/progs/stratumd`. All 30+ static libs
that stratumd's dependency tree pulls in (stm_util, stm_fs, stm_9p,
stm_lp9, stm_block, stm_crypto, ...) compile without modification --
the existing platform-conditional sites in 10 other files in `src/`
fall through cleanly on Thylacine without a third arm.

## Why this branch off main

`phase-9.7` (the Stratum agent's active branch as of 2026-05-24) has
untracked audit-WIP files (`.audit_r*_findings.md`) and an R171 close
that the Stratum agent had just landed. Branching from `main` (which
is now at the R172 close `976cb6f`, ahead of `phase-9.7` by two
commits) gives a clean base with zero entanglement with the in-flight
crown-jewel arc. **The Stratum agent merges this branch forward when
convenient -- no time pressure** -- by `git merge thylacine-pouch-arm`
into main (or into `phase-9.7` first if preferred, then forward).

## What changed in detail

### CMakeLists.txt -- Thylacine platform detection

Added right after the Linux/Darwin detection (line ~53):

```cmake
elseif(CMAKE_C_COMPILER_TARGET STREQUAL "aarch64-thylacine")
    # Thylacine cross-compile via pouch. The pouch CMake toolchain
    # (thylacine/cmake/Toolchain-aarch64-pouch.cmake) sets
    # CMAKE_SYSTEM_NAME=Generic + CMAKE_C_COMPILER_TARGET=aarch64-thylacine
    # + -D__thylacine__ + -D_GNU_SOURCE at the toolchain level; we set
    # STM_PLATFORM_THYLACINE here so per-platform branches below stay
    # symmetric with Linux/Darwin.
    set(STM_PLATFORM_THYLACINE TRUE)
endif()
```

The `CMAKE_SYSTEM_NAME` is "Generic" (the CMake convention for unknown
OS targets); we detect Thylacine via `CMAKE_C_COMPILER_TARGET` which
the Thylacine-side toolchain sets to `aarch64-thylacine`.

### CMakeLists.txt -- Threads + libsodium + PkgConfig

Replaces the `find_package(Threads)` / `find_package(PkgConfig)` /
`pkg_check_modules(LIBSODIUM)` block at line ~144 with a
platform-conditional version. On Thylacine, the IMPORTED targets are
synthesized manually:

```cmake
if(STM_PLATFORM_THYLACINE)
    # pouch's musl bundles pthread in libc; libsodium ships pre-built
    # in the cross-sysroot without a .pc file. Synthesize the IMPORTED
    # targets the rest of the tree references.
    add_library(Threads::Threads INTERFACE IMPORTED)
    add_library(PkgConfig::LIBSODIUM INTERFACE IMPORTED)
    set_property(TARGET PkgConfig::LIBSODIUM PROPERTY
        INTERFACE_LINK_LIBRARIES sodium)
    # Sodium headers come via the toolchain's -isystem ${SYSROOT}/include;
    # no explicit INTERFACE_INCLUDE_DIRECTORIES needed.
else()
    find_package(Threads REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.19)
endif()
```

Existing Linux + Darwin builds are unaffected (the `else()` branch is
byte-identical to the prior code).

### CMakeLists.txt -- skip `_FORTIFY_SOURCE` on Thylacine

The `_FORTIFY_SOURCE=2` gate (line ~102) was `NOT STM_PLATFORM_DARWIN
AND STM_SANITIZE STREQUAL "off"`; it now also skips Thylacine because
musl doesn't implement `_FORTIFY_SOURCE`. The macro would be a no-op
there; setting it adds noise and the cross-compile flag set stays
minimal:

```cmake
if(NOT STM_PLATFORM_DARWIN AND NOT STM_PLATFORM_THYLACINE AND STM_SANITIZE STREQUAL "off")
    target_compile_options(stm_warnings INTERFACE -D_FORTIFY_SOURCE=2)
endif()
```

### src/cmd/stratumd/peer_creds.c -- the Thylacine arm

Extends the `__linux__` arm guard at line 15 (the `#if defined`
include guard) and line 25 (the `#if defined` function-body branch)
to `__linux__ || __thylacine__`. The function body of the Linux arm
(`getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len)`) is reused
unchanged.

The Thylacine pouch musl's `getsockopt(SO_PEERCRED)` arm (added in
the Thylacine repo by `0006-pouch-sockets.patch` at sub-chunk 12)
marshals the call onto Thylacine's `SYS_srv_peer` underneath. The
returned `struct ucred` has:
- `pid` = peer stripes (low 31 bits)
- `uid` = 0 at v1.0 (Thylacine has no uid model)
- `gid` = 0 at v1.0

Stratum's `stm_peer_creds(int fd, uid_t *out_uid, gid_t *out_gid)`
contract is **uid + gid** -- it doesn't consume pid -- so the
lossiness of the ucred marshal is tolerable for Stratum's existing
uid-based ACLs (every peer looks like uid=0; the ACL is effectively
a no-op until Thylacine grows a uid model). POUCH-DESIGN.md section 10
envisions a richer `t_srv_peer` arm exposing the full kernel-stamped
record (live caps + stripes + console bit + alive bit); deferred to
v1.x when Thylacine has a uid model and the lossiness becomes
load-bearing.

Added comment block explains the Thylacine arm + the marshal behavior.

## How Thylacine consumes this

In `~/projects/thylacine/tools/build.sh` -- a new `build_stratumd`
function -- the cross-build invocation:

```sh
cmake -S "$STRATUM_SRC" -B "$stratumd_build" \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_ROOT/cmake/Toolchain-aarch64-pouch.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DSTM_ENABLE_PQ=OFF \
    -DSTM_ENABLE_IOURING=OFF \
    -DSTM_ENABLE_LIBAIO=OFF \
    -DSTM_BUILD_TESTS=OFF \
    -DSTM_BUILD_FUZZERS=OFF \
    -DSTM_WERROR=OFF \
    -DSTRATUM_BUILD_TESTING_HOOKS=OFF
cmake --build "$stratumd_build" --target stratumd
```

The Thylacine pouch toolchain (`cmake/Toolchain-aarch64-pouch.cmake`)
sets at the toolchain level: `-D__thylacine__=1`, `-D_GNU_SOURCE=1`,
`-march=armv8-a+lse+pauth+bti`, `-nostdlibinc -isystem $sysroot/include`,
hardening flags, and a `CMAKE_C_LINK_EXECUTABLE` override that routes
the link through `tools/pouch-ld` (which drives `ld.lld` directly --
clang as a link driver mis-selects the host Darwin toolchain for the
unknown `aarch64-thylacine` triple on macOS).

Output: 860536-byte static ET_EXEC at
`<thylacine>/build/pouch/progs/stratumd`. Symbol checks pass:
`stm_peer_creds` defined; `stm_stratumd_run` defined; `main` defined.
ET_EXEC + no PT_DYNAMIC + GNU_RELRO + W^X clean.

## What's NOT in this branch

Per POUCH-DESIGN.md section 14 row 15, this sub-chunk is **build only**:

- stratumd is NOT yet spawned in Thylacine -- that's
  Thylacine-side sub-chunk 16 (`pouch-stratumd-boot`), where joey
  spawns it and pivots ramfs to `/sysroot`.
- The binary is NOT yet added to Thylacine's ramfs.
- No runtime behavior change in Stratum's normal Linux/Darwin builds
  (the `else()` branch of the new conditional is byte-identical).
- No new audit needed (per POUCH-DESIGN.md section 14 row 15 the
  cross-build is NOT audit-bearing -- pouch's surface is unchanged).

## When stratumd actually runs on Thylacine (sub-chunk 16+)

Sub-chunk 16 will likely surface pouch-side gaps that the cross-build
doesn't (a pure compile can succeed against ENOSYS-stubbed syscalls;
runtime exercises them). Anticipated:
- `mlock` returns ENOSYS via pouch's `0xFFFF` sentinel -- corvus_client
  uses it as best-effort for the session-token buffer; the failure
  path may need to be tolerated.
- `mprotect`/`madvise` similarly stubbed.
- `statfs`/`fstatfs` may need pouch arms.
- Some 9P pipelining might surface kernel client gaps.

Those are sub-chunk 16's surface, not this sub-chunk's. The
cross-build proves the toolchain + the platform-arm pattern;
runtime proof is sub-chunk 16.

## Cross-references

- Thylacine repo: `docs/POUCH-DESIGN.md` section 10 -- the per-OS arm
  pattern.
- Thylacine repo: `docs/POUCH-DESIGN.md` section 14 row 15 --
  sub-chunk 15 scope.
- Thylacine repo: `docs/reference/85-pouch-stratumd-build.md` -- the
  detailed reference doc on this integration.
- Thylacine repo: `cmake/Toolchain-aarch64-pouch.cmake` -- the pouch
  cross-toolchain.
- Stratum repo (this branch): the two file changes above.

## Merge guidance

When the Stratum agent picks this up: this branch is a clean topic
branch off `main`@`976cb6f` with two file changes that are
strictly-additive (new `elseif` arm; new `__thylacine__` branch in an
existing `#if` chain). No existing test should regress on Linux or
Darwin. ctest hosts continue to use `find_package(Threads)` +
`pkg_check_modules(LIBSODIUM)` as before.

Merging into `main` (or forward through `phase-9.7`) is at the
agent's discretion -- there's no time pressure from the Thylacine
side; the cross-build re-runs cleanly from `tools/build.sh stratumd`
in the Thylacine tree even if these changes live on a branch for
weeks.

-- Thylacine session (2026-05-24)
