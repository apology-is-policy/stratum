# Session handoff — 2026-05-26 — Thylacine `--seed` flag for stratum-mkfs

**Branch**: `thylacine-pouch-arm`
**Commit**: pending (will be pushed by the user)
**Scope**: ONE file, ~50 lines.

## What this adds

A new `--seed HEX64` flag on `stratum-mkfs`. When provided, the pool
and device UUIDs are derived deterministically from the seed instead
of from `clock_gettime + getpid()`. Same seed → identical UUIDs across
runs.

## Why

Thylacine is investigating a content-sensitive memory-corruption bug
inside stratumd's pool-mount path (libsodium AEGIS-256 soft decrypt
triggers mallocng heap corruption on certain decrypted byte
patterns). The bug fires with some `pool.img` contents and not
others. Reproducing it requires pinning the pool's on-disk byte
layout across builds.

Today's behavior: `tools/build.sh build_stratum_pool_fixture`
regenerates `pool.img` on every kernel build (the file is `rm -f`'d
before each call to `stratum-mkfs`), so each build's UUID is
different. The seed flag lets the Thylacine build script pass a
deterministic value, giving us a pinning point.

## Important caveat

`--seed` pins only the **UUID derivation**. The pool's on-disk bytes
are still NOT byte-identical across runs because:

- The keyfile is regenerated each run (uses libsodium
  `randombytes_buf`, which is per-process random).
- libsodium uses fresh nonces during the bootstrap pool format.

For **full byte reproduction**, callers must ALSO pin the keyfile
(e.g., `--keyfile <existing-file>` so the existing keyfile is reused
instead of regenerated). Even then, the libsodium-nonce entropy
remains a small per-run delta; complete byte-pinning would need
libsodium RNG seeding (out of scope for this change).

For our use case (Thylacine bug investigation), the practical
recipe is:

1. Run a build with `--seed 0xCAFE` (any fixed value).
2. If the build triggers the AEGIS bug, save `pool.img` AND
   `pool.img.key`.
3. Subsequent builds reuse both files (skip `stratum-mkfs`
   regeneration) → byte-identical → bug reproduces.

The Thylacine-side build script gets a paired `THYLACINE_MKFS_PRESERVE=1`
env var that skips `stratum-mkfs` and reuses existing files.

## Files touched

`src/cmd/stratum-mkfs/run.c`:
- New `parse_hex64` helper (parses optional `0x` + up to 16 hex chars).
- New static globals `g_mkfs_seed_set` + `g_mkfs_seed`.
- `derive_uuid` consults the globals; falls back to `time+pid` if
  unset.
- `--seed HEX64` arg parsing in the main loop.
- Log line after format showing the effective seed (pinned vs
  time+pid mode).
- Help text update for `--seed`.

## Validation

```
$ build/src/cmd/stratum-mkfs/stratum-mkfs /tmp/p1.img --size 32M --seed 0xCAFE
stratum-mkfs: seed=0x000000000000cafe (pinned via --seed)
formatting /tmp/p1.img (33554432 bytes)...
ok: /tmp/p1.img ready (dataset 1 root ino=1)

$ build/src/cmd/stratum-mkfs/stratum-mkfs /tmp/p2.img --size 32M --seed 0xCAFE
stratum-mkfs: seed=0x000000000000cafe (pinned via --seed)
formatting /tmp/p2.img (33554432 bytes)...
ok: /tmp/p2.img ready (dataset 1 root ino=1)

$ cmp /tmp/p1.img /tmp/p2.img
/tmp/p1.img /tmp/p2.img differ: char 16497, line 1
```

The bytes differ at offset 16497 — that's the libsodium-nonce
entropy in the bootstrap pool's superblock. Expected per the caveat
above. UUIDs (at fixed offsets earlier in the file) ARE identical.

## Cross-project

Thylacine-side: `tools/build.sh::build_stratum_pool_fixture` gains
`THYLACINE_MKFS_SEED` (passes `--seed`) AND `THYLACINE_MKFS_PRESERVE`
(skips regen). Landed in the matching Thylacine commit.

## Disposition

Lands on `thylacine-pouch-arm` branch. Does NOT merge to `main`
unless/until a cross-platform use case emerges (the flag is harmless
on Linux; it's just unused there). User pushes manually.
