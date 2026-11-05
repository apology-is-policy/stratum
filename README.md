# Stratum v2

This tree is the v2 implementation of Stratum, built against the Phase 0 design
documents at the repository root (`docs/VISION.md`, `docs/COMPARISON.md`,
`docs/NOVEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP-V2.md`).

v1 lives as-is under `../src/`, `../include/`, `../tests/`, `../tui/`. v2 does
not share code with v1 — anything salvaged is ported through an explicit review
pass and re-lands here with its own audit. The two trees share the design
documents and nothing else.

## Layout

```
v2/
├── CMakeLists.txt            # top-level build, sanitizer variants, CI hooks
├── cmake/                    # cmake modules (FindLibsodium, FindLiboqs, …)
├── include/stratum/          # public headers for each subsystem
├── src/
│   ├── block/                # Phase 1 — block device abstraction
│   ├── crypto/               # Phase 1 — AEAD + KDF + PQ wrap
│   ├── hash/                 # Phase 1 — BLAKE3 + xxHash3 wrappers
│   └── util/                 # shared utilities (errors, endian, atomic)
├── third_party/              # vendored reference implementations
│   ├── BLAKE3/               # official BLAKE3 reference
│   └── xxhash/               # Cyan4973/xxHash
├── tests/                    # unit + property-based + fuzzer hooks
├── specs/                    # TLA+ specs + SPEC-TO-CODE mapping
└── ci/                       # GitHub Actions workflow
```

## Dependencies

System-provided (find_package / pkg-config):

- **libsodium** ≥ 1.0.19 — AEGIS-256 (via `crypto_aead_aegis256_*`), XChaCha20,
  Poly1305, X25519, Argon2id, random.
- **liboqs** ≥ 0.9.0 — ML-KEM-768 for PQ-hybrid key wrap.
- **liburing** ≥ 2.3 — Linux io_uring backend (Linux only).
- **CMake** ≥ 3.24.
- **C17** compiler (GCC ≥ 11 / Clang ≥ 14).

Vendored under `third_party/`:

- **BLAKE3** — official reference C implementation.
- **xxHash** — `xxhash.h` single-header.

## Build

```
cmake -B build -S .                           # default release-with-asserts
cmake -B build -S . -DSTM_SANITIZE=asan       # address+undefined sanitizers
cmake -B build -S . -DSTM_SANITIZE=tsan       # thread sanitizer
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF  # POSIX backend only
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Build options

| Flag                        | Default   | Effect                                    |
|-----------------------------|-----------|-------------------------------------------|
| `STM_SANITIZE`              | `off`     | `asan`, `tsan`, `msan`, `ubsan`, `off`    |
| `STM_ENABLE_IOURING`        | auto      | Linux io_uring backend; auto-detects      |
| `STM_ENABLE_LIBAIO`         | `OFF`     | pre-5.1 Linux compat backend (opt-in)     |
| `STM_AEAD_DEFAULT`          | `auto`    | `aegis256`, `xchacha20-siv`, `auto`       |
| `STM_ENABLE_PQ`             | `ON`      | liboqs ML-KEM-768 hybrid wrap             |
| `STM_BUILD_TESTS`           | `ON`      | test binaries                             |
| `STM_BUILD_FUZZERS`         | `OFF`     | libFuzzer targets (needs clang)           |
| `STM_COVERAGE`              | `OFF`     | gcov/lcov instrumentation                 |

## Status

**Phase 1 — Foundations.** See `../docs/ROADMAP-V2.md` §4.
