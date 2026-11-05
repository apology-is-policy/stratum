# Session handoff: Thylacine mmap-bypass for btree decrypt scratch

**Date**: 2026-05-25
**Branch**: `thylacine-pouch-arm`
**Tip on handoff**: TBD (one new commit on this branch)
**Counter-party agent**: Stratum agent (paused during this change)

## Summary

One narrow targeted change to `src/btree_store/crypt.c` (in `stm_btree_node_decrypt`)
that adds a `#ifdef __thylacine__` branch using `mmap(MAP_ANONYMOUS)` instead of
`malloc()` for the ciphertext scratch buffer. Other platforms keep the existing
`malloc` path byte-identically.

## Why

Pouch musl's mallocng exhibits slot-footer corruption on the second 128 KiB
alloc/free cycle (sizeclass-63 path, allocations above MMAP_THRESHOLD = 131052
bytes). The root cause has been narrowed but not identified -- the byte-copy
operation in `stm_btree_node_decrypt` is provably correct (writes only
`[ct, ct+node_size)`) but ct's slot footer at `ct[node_size+0..16]` and
`ct[node_size+3860..3868]` is corrupted post-memcpy. Detailed deep-dive at
Thylacine `docs/reference/86-pouch-stratumd-boot.md` "16b-γ-mount-bind deep-dive
(Finding 2 narrowing)".

In-place decrypt was considered but is blocked by the existing Stratum comment
(lines 27-37 of crypt.c) -- AEGIS-256 in libsodium is empirically NOT safe under
aliased ct/pt (produces zero plaintext). The mmap-bypass eliminates mallocng's
slot metadata entirely (page-grain mmap has no allocator-side footer at
`ct[node_size..]` for memcpy's adjacency to perturb).

## Scope

- Only `stm_btree_node_decrypt`. `stm_btree_node_encrypt` uses
  `malloc(ciphertext_len)` where ciphertext_len < MMAP_THRESHOLD (131040 vs
  131052), so it doesn't hit sizeclass 63 and isn't affected.
- The Linux + glibc path is byte-identically preserved via `#ifdef __thylacine__`.
- libsodium's internal mallocs are unaffected.

## Verification

Could NOT be verified end-to-end yet because of a SEPARATE bug discovered
upstream of this code path: `bdev_thylacine.c` (this branch's earlier commit
`63a3eb1`) sends a zero-sized virtio descriptor at approximately the 113th
sequential read during `stm_sb_mount_scan`'s label×slot iteration. QEMU rejects
with `virtio: zero sized buffers are not allowed`. This blocks the path BEFORE
the decrypt scratch is exercised, so the mmap fix is in-place but currently
dormant.

When the bdev_thylacine read-loop bug is fixed (separate session; Thylacine
docs/reference/86-pouch-stratumd-boot.md captures the symptom), the mmap fix
unblocks stratumd's mount of the 64 MiB integrity-only system pool that joey
hands over.

## What's not touched

- Encrypt path
- All other mount-related code
- All other btree_store / sync / fs paths
- Linux glibc default behavior
- libsodium

## Files changed

```
v2/src/btree_store/crypt.c (27 lines added, 1 deleted)
```

## Forward-merging guidance

The change is gated by `#ifdef __thylacine__`. Safe to merge to `main` if the
agent prefers a single-codepath strategy, OR keep on the `thylacine-pouch-arm`
branch as a Thylacine-only carve-out. Either is fine; the gate makes it
inert on non-Thylacine platforms.

## Co-action

Thylacine-side documentation updates ride this:
- `docs/reference/86-pouch-stratumd-boot.md` extends the 16b-γ-mount-bind
  deep-dive section with the mmap-bypass approach + the bdev_thylacine
  upstream-blocker discovered this session.
- `docs/phase6-status.md` row capturing this session.
- Memory files updated.

User pushes both Stratum-side and Thylacine-side commits.
