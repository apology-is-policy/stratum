# Stratum

Stratum is a copy-on-write filesystem in C17 with encryption and integrity built into its format.
There is no unencrypted mode: file data and nearly all metadata are sealed with AEGIS-256, and
metadata nodes are chained to the root by BLAKE3 hashes of their ciphertext.

It runs in user space and serves POSIX-shaped files over 9P2000.L. A single Rust binary, `stratum`,
packages the daemons with a dual-pane file manager, so a volume can also be used as an encrypted
container file.

**It is not production-ready.** The on-disk format is not frozen, there is no filesystem checker, and
several features exist only as library calls. **Read [docs/SPECIFICATION.md](docs/SPECIFICATION.md)**:
it covers the design, the trade-offs against ZFS, btrfs and bcachefs, what is and is not built, the
hard limits, and the known defects.

## Use it as an encrypted volume

```
./dist.sh                                                  # builds dist/stratum

dist/stratum mkfs vault.stm --size 4G --passphrase-stdin   # create a volume
dist/stratum tui --vol vault.stm                           # open it in the manager
```

In the manager, `F5` copies between the host and the volume, `F7` makes a directory, `F8` deletes and
`F9` handles snapshots. To script the same thing, serve the volume and talk to its socket:

```
dist/stratum serve vault.stm --listen /tmp/vault.sock --passphrase-stdin
dist/stratum fs -s /tmp/vault.sock put ./photos /photos
dist/stratum fs -s /tmp/vault.sock ls /photos
```

Each mutating `stratum fs` command, and each item the manager copies, ends with a whole-pool commit. So
what it reports done is durable, and copying many small files is slow.

A volume needs its keyfile, by default `<volume>.key` beside it. `--passphrase-stdin` seals that keyfile
with Argon2id; without it the keyfile is plaintext. Losing the keyfile loses the volume. Do not copy a
volume and go on writing to both copies, because that can reuse AEAD nonces (specification, section 9.4).

## Dependencies

- A C17 compiler (GCC 11 or later, Clang 14 or later) and CMake 3.24 or later.
- **libsodium** 1.0.19 or later, for AEGIS-256, X25519, Argon2id and random numbers.
- **liboqs** 0.9.0 or later for the ML-KEM-768 half of the key wrap. Optional: without it the build
  warns and falls back to X25519 alone, so **the key wrap is not post-quantum in that build**.
- **liburing** 2.3 or later, on Linux, for the io_uring backend.
- **Rust** and Cargo, for the `stratum` binary.

BLAKE3 and xxHash are vendored under `third_party/`.

## Build and test

```
cmake -B build -S .
cmake --build build -j
ctest --test-dir build --output-on-failure

(cd tools/stratum && STM_BUILD_DIR="$PWD/../../build" cargo test --release)
```

The Rust crate links the static libraries from a prior CMake build. `STM_BUILD_DIR` says where it is.

| Flag | Default | Effect |
|---|---|---|
| `STM_SANITIZE` | `off` | `asan`, `tsan`, `msan`, `ubsan` |
| `STM_ENABLE_IOURING` | `ON` | io_uring backend, Linux only |
| `STM_ENABLE_LIBAIO` | `OFF` | libaio backend for pre-5.1 Linux |
| `STM_ENABLE_PQ` | `ON` | ML-KEM-768 hybrid key wrap, using liboqs |
| `STM_BUILD_TESTS` | `ON` | Test binaries |
| `STM_BUILD_BENCHES` | `OFF` | Benchmarks |
| `STM_BUILD_FUZZERS` | `OFF` | Reserved; there are no fuzz targets yet |
| `STM_COVERAGE` | `OFF` | gcov instrumentation |
| `STM_WERROR` | `ON` | Warnings are errors |

## Layout

```
include/stratum/    public headers, one per subsystem
src/                the filesystem, one directory per subsystem
src/cmd/            stratumd and the other daemons
tools/stratum/      the stratum binary and the file manager
tests/              the C test suites
specs/              TLA+ models, with deliberately broken configurations that must fail
docs/               the specification, design documents and reference
third_party/        vendored BLAKE3 and xxHash
```

Start with `docs/SPECIFICATION.md`, which was checked against the code. The older design documents
(`docs/VISION.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`) record intent, and some of their statements
are out of date.
