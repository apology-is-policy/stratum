# Stratum — The Definitive Technical Reference

**Version**: repository state at commit `0d674ee` (SOTA #1 FUSE backend), updated through the R0–R14 soundness audit loop, Phase A–C feature work, SOTA #5 POSIX completion, and Phase D item #8 (AEAD AD binding — ss_version bumped to 2). The three-phase sync and AEAD nonce invariant machinery in §7 and §23 is load-bearing — see `CLAUDE.md` for the audit-triggering change policy.
**Scope**: This document describes every user-visible behavior, every on-disk structure, every algorithm, and every known quirk of the Stratum filesystem. It is written to be exhaustive: a future engineer should be able to reimplement Stratum from scratch using only this document, or debug any concrete issue without reading the source.

---

## Table of Contents

1. [Overview](#1-overview)
2. [On-disk layout](#2-on-disk-layout)
3. [The Bε-tree](#3-the-bε-tree)
4. [Extent-based data storage](#4-extent-based-data-storage)
5. [Block allocator](#5-block-allocator)
6. [Copy-on-write (COW)](#6-copy-on-write-cow)
7. [Crash safety](#7-crash-safety)
8. [Filesystem layer](#8-filesystem-layer)
9. [Encryption](#9-encryption)
10. [Compression](#10-compression)
11. [Integrity checksums](#11-integrity-checksums)
12. [Snapshots](#12-snapshots)
13. [9P protocol server](#13-9p-protocol-server)
14. [CLI (stratum)](#14-cli-stratum)
15. [TUI (stratum-tui)](#15-tui-stratum-tui)
16. [FUSE backend (stratum-fuse)](#16-fuse-backend-stratum-fuse)
17. [Build system](#17-build-system)
18. [Testing](#18-testing)
19. [Performance characteristics](#19-performance-characteristics)
20. [Edge cases and gotchas](#20-edge-cases-and-gotchas)
21. [Known limitations / future work](#21-known-limitations--future-work)
22. [Glossary](#22-glossary)
23. [Soundness invariants](#23-soundness-invariants)

---

## 1. Overview

Stratum is a **user-space copy-on-write filesystem** that stores a single volume in a regular host file (so-called "file-backed" volume). It exposes the volume to applications over the **9P2000** protocol (with Stratum-specific extensions for snapshot operations). The system ships as two binaries:

- `stratum` — a C program providing `mkfs`, `serve` (9P server), `info`, `check`, `snap`.
- `stratum-tui` — a Rust TUI (ratatui) dual-pane file manager that starts a `stratum serve` child and acts as its 9P client, plus a headless CLI mode for scripting.

### 1.1 Design goals

- **Correctness on crash** — any torn write must leave the previous transaction intact.
- **Data integrity** — per-block xxHash3-128 checksums detect bit rot; optional XChaCha20-Poly1305 encryption provides AEAD integrity.
- **Space efficiency** — LZ4 or ZSTD compression for both Bε-tree nodes and file-data extents; COW deferred-free to avoid double allocation.
- **Scalability** — Bε-tree absorbs point writes in an internal message buffer, batching them into leaves.
- **Snapshots** — O(1) create, refcount-based block sharing, rollback, deletion, accessible via TUI and 9P.
- **Pluggable storage** — block device is a vtable (`struct stm_block_ops`), the file backend is the first implementation.

### 1.2 Non-goals

- **POSIX-complete semantics** — hard links, symlinks, extended attributes (`STM_KEY_XATTR` is reserved but not implemented), permissions/ACLs, `utimes`, `rename`, `truncate`, `mmap`. Only `mkdir`, `create`, `read`, `write`, `readdir`, `stat`, `unlink` are wired through.
- **Multi-client concurrency** — the file backend takes `flock(LOCK_EX|LOCK_NB)` on open; only one `stratum serve` process can hold a given volume at a time. Multiple 9P clients may connect to one server but their requests are serialized (the server is single-threaded).
- **Block-device backend** — only file-backed volumes exist.
- **Journaling / WAL** — crash safety is provided purely by COW + ping-pong superblocks.
- **Defragmentation** — no user-visible defrag.
- ~~**Kernel FUSE mount** — there is no FUSE bridge.~~ **Landed (§16).** Applications can talk 9P or mount the volume via `stratum-fuse`.

### 1.3 Relation to other COW filesystems

| Feature | Stratum | btrfs | ZFS | APFS |
| --- | --- | --- | --- | --- |
| Data structure | **Bε-tree** | B-tree | object set + tree | B-tree |
| Block integrity | xxHash3-128 | CRC32C | fletcher2/4 / SHA-256 | none |
| Encryption | per-block XChaCha20-Poly1305 (nonce = paddr ‖ write_gen) | via dm-crypt | AES-CCM/GCM | AES-XTS |
| Compression | per-node + per-extent LZ4 / ZSTD | per-extent LZO/ZSTD | per-block LZ4/ZSTD/gzip | LZFSE/ZLib |
| Snapshots | refcount-based, saved root bptr | same | same | same |
| Superblock | ping-pong (2 slots) | multiple copies | uberblock ring | container superblock |
| Auto-grow | yes (proportional ftruncate) | no | pools | container resize |
| Interface | 9P2000 server | kernel FS | kernel FS + user | kernel FS |
| Commit model | tree flush + single fsync | transactional | txg groups | checkpoints |

### 1.4 Architecture diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ Applications (TUI, editor, any 9P client)                       │
└──────────────────────┬──────────────────────────────────────────┘
                       │ 9P2000 (+ Stratum snap extensions) over Unix/TCP
┌──────────────────────▼──────────────────────────────────────────┐
│  stratum serve  ── src/cmd/stratum.c::cmd_serve                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 9P Server ── src/p9/p9.c                                 │   │
│  │   • Fid table (256 entries)                              │   │
│  │   • Handlers: version/attach/walk/open/create/read/write │   │
│  │   • Extensions: snap_create/list/delete/rollback         │   │
│  └───────────────────┬──────────────────────────────────────┘   │
│  ┌───────────────────▼──────────────────────────────────────┐   │
│  │ Filesystem layer ── src/fs/fs.c                          │   │
│  │   • Inodes, dirents (FNV1a + linear probe)               │   │
│  │   • Read/write via extents                               │   │
│  │   • mkdir, create, unlink, readdir, stat                 │   │
│  └───────┬──────────────────────────┬───────────────────────┘   │
│          │                          │                           │
│  ┌───────▼────────┐         ┌───────▼────────┐                  │
│  │ Bε-tree        │         │ Snapshot tree  │                  │
│  │ src/btree/     │         │ src/snap/      │                  │
│  └───────┬────────┘         └───────┬────────┘                  │
│          └──────┬───────────────────┘                           │
│  ┌──────────────▼──────────────┐   ┌────────────────────────┐   │
│  │ Allocator ── src/alloc/     │   │ Crypto, compress, csum │   │
│  └──────────────┬──────────────┘   └────────────────────────┘   │
│  ┌──────────────▼──────────────────────────────────────────┐    │
│  │ Block device ── src/block/file_backend.c                │    │
│  │   pread / pwrite / fsync / ftruncate / flock(LOCK_EX)   │    │
│  └──────────────────────────┬──────────────────────────────┘    │
└────────────────────────────┬┴───────────────────────────────────┘
                  ┌──────────▼──────────┐
                  │  /path/to/vol.stm   │   (single regular file)
                  └─────────────────────┘
```

---

## 2. On-disk layout

### 2.1 Units and constants

| Constant | Value |
| --- | --- |
| `STM_BLOCK_SIZE` | 4096 (4 KiB) |
| `STM_NODE_SIZE` | 131072 (128 KiB) |
| `STM_EXTENT_SIZE` | 131072 (128 KiB) |
| `STM_EXTENT_BLOCKS` | 32 |
| `STM_MAGIC` | `0x004d555441525453` = `"STRATUM\0"` LE |
| `STM_BADDR_NONE` | `0xFFFFFFFFFFFFFFFF` |
| `STM_CSUM_LEN` | 32 |

All integers are stored little-endian. Types `le64`/`le32`/`le16` wrap `uint*_t` in packed structs so the compiler rejects implicit conversions.

### 2.2 Volume file layout

```
Offset         Size     Content
──────────── ────────   ───────────────────────────────
0x00000000    4 KiB     Superblock A (block 0)
0x00001000    4 KiB     Superblock B (block 1)
0x00002000    …         Btree nodes, extent data, snap tree nodes
                        (interleaved, allocated by refcount allocator)
```

Block addresses in `stm_bptr::bp_paddr` are **byte offsets**. `paddr / STM_BLOCK_SIZE` gives the block number.

### 2.3 `struct stm_superblock` (512 bytes)

```
Offset Size   Field                     Notes
──────  ────   ────────────────────     ──────────────────────────
0       8      le64    ss_magic          = STM_MAGIC
8       4      le32    ss_version        currently 2 (Phase D AEAD AD binding)
12      4      le32    ss_flags          unused (0)
16      8      le64    ss_gen            monotonic per-sync
24      57     stm_bptr ss_root          root of main Bε-tree
81      57     stm_bptr ss_snap_root     root of snapshot tree
138     57     stm_bptr ss_space_root    reserved (always null)
195     2      le16    ss_tree_height    height of main tree
197     4      le32    ss_block_size     = 4096
201     4      le32    ss_node_size      = 131072
205     8      le64    ss_total_blocks   blocks at last sync
213     8      le64    ss_free_blocks    always 0 — rebuilt on mount
221     8      le64    ss_next_ino       next inode to allocate
229     1      u8      ss_enc_algo       0=none, 1=XChaCha20, 2=reserved
230     32     u8[32]  ss_enc_kdf_salt   Argon2id salt
262     64     u8[64]  ss_enc_wrapped_key  DEK wrapped with KEK (48B used)
326     24     u8[24]  ss_enc_nonce      nonce used to wrap DEK
350     1      u8      ss_comp_algo      0=none, 1=LZ4, 2=ZSTD (file-data)
351     8      le64    ss_alloc_next     legacy bump-allocator cursor
359     2      le16    ss_snap_height    height of snap tree
361     8      le64    ss_next_snap_id   next snapshot id
369     32     u8[32]  ss_csum           xxHash3-128 + zero padding
401     111    u8[111] ss_reserved       padding
```

### 2.4 `struct stm_bptr` (57 bytes)

```
0       8      le64    bp_paddr          physical byte address
8       8      le64    bp_write_gen      write-gen counter (AEAD nonce uniqueness)
16      32     u8[32]  bp_csum           checksum of on-disk bytes
48      1      u8      bp_comp           0=none, 1=LZ4, 2=ZSTD
49      4      le32    bp_csize          compressed size on disk
53      4      le32    bp_lsize          uncompressed size
```

### 2.5 `struct stm_key` (17 bytes)

```
0       8      le64    sk_ino            inode number
8       1      u8      sk_type           key type (see below)
9       8      le64    sk_offset         type-specific offset
```

Key types:

| Value | Name | Meaning of `sk_offset` |
| --- | --- | --- |
| 0x01 | `STM_KEY_INODE` | always 0 |
| 0x02 | `STM_KEY_DIRENT` | FNV1a hash + collision probe |
| 0x03 | `STM_KEY_DATA` | byte offset of 128 KiB extent |
| 0x04 | `STM_KEY_XATTR` | reserved, unused |
| 0x05 | `STM_KEY_SNAP` | snapshot id |
| 0x06 | `STM_KEY_SNAP_NAME` | hash of snapshot name + probe |

Sort order is lexicographic `(ino, type, offset)`. All data for one inode is contiguous in the tree.

### 2.6 `struct stm_inode` (88 bytes)

Contains ino, gen, mode, uid, gid, nlink, size, atime/mtime/ctime (sec + nsec), and flags. Stored under `(ino, STM_KEY_INODE, 0)`.

### 2.7 `struct stm_extent` (24 bytes)

```
0       8      le64    se_paddr           on-disk address of extent data
8       8      le64    se_write_gen       write-gen counter (AEAD nonce uniqueness)
16      4      le32    se_dlen            logical (uncompressed) data length
20      4      le32    se_clen_and_comp   low 24 bits: stored disk length (pre-AEAD-tag)
                                          high 8 bits: compression algo (STM_COMP_*)
```

Stored as the btree value for `STM_KEY_DATA` keys.

`se_write_gen` holds `fs->gen` at encrypt time. The crypto layer feeds `(paddr, write_gen)` into the XChaCha20-Poly1305 nonce so a paddr reused across free+realloc produces a distinct (key, nonce) pair. It's populated on unencrypted volumes too, for format consistency.

The compression algo is packed into the high byte of `se_clen_and_comp`; the low 24 bits hold the stored length on disk (covers up to 16 MiB, more than enough for the 128 KiB max extent). If compression did not shrink the data, the raw form is stored and `se_clen == se_dlen`, `comp == STM_COMP_NONE`.

Access via helpers:

```c
uint32_t stm_extent_clen(const struct stm_extent *e);
uint8_t  stm_extent_comp(const struct stm_extent *e);
void     stm_extent_set(struct stm_extent *e, uint64_t paddr,
                        uint64_t write_gen,
                        uint32_t dlen, uint32_t clen, uint8_t comp);
```

### 2.8 `struct stm_node_hdr` (64 bytes)

Prefix of every btree node on disk: magic, level, flags, nkeys, nmsgs, msg_bytes, data_bytes, gen, plus a reserved 32-byte csum field.

---

## 3. The Bε-tree

### 3.1 Why a Bε-tree

A Bε-tree buffers inserts as **messages** in per-internal-node buffers. When a buffer fills, messages are pushed to the heaviest child. This amortizes insert cost across batches instead of paying one leaf rewrite per insert.

### 3.2 Node layout

- **Leaf**: sorted entries `[key(17) + vlen(4) + value]`.
- **Internal**: pivots, `nkeys+1` child bptrs, message buffer `[msg_header(30) + value]`.

Fill threshold: 90% of node body triggers a split.

### 3.3 Message ordering

Messages sort by `(key, gen ascending)`. Binary search in `stm_msg_insert` uses `<=` so new messages are inserted **after** equal entries; `stm_msg_find` returns the **last** match. This ensures the newest insert wins when multiple messages share the same key and generation.

### 3.4 Drain-free scan

`stm_btree_scan` does NOT flush messages to leaves. Instead, it carries pending INSERT messages down through descent, merging them with leaf entries at read time. This eliminates the expensive full-tree drain that previously happened on every readdir and unlink.

### 3.5 Operations

- **Lookup**: descend tracking highest-gen pending message per key.
- **Insert**: buffer a message in root; flush on buffer overflow; split root on node overflow.
- **Delete**: buffer DELETE message (or delete directly from leaf root).
- **Flush**: `drain_all` recursively pushes messages to leaves via two-phase recursion.
- **Scan**: drain-free range iteration.

### 3.6 Splits

- Leaf split: divide by entry count.
- Internal split: divide pivots at midpoint, promote `pivots[mid]`, partition messages by key.
- Root split: create new internal root wrapping both halves; `tree->height++`.

---

## 4. Extent-based data storage

### 4.1 Model

File data lives on disk OUTSIDE the btree. The btree stores only 16-byte `stm_extent` records pointing to where the data lives. Each extent covers up to 128 KiB of logical data, stored on disk in compressed and/or encrypted form.

### 4.2 Write path (`stm_fs_write` → `extent_write_data`)

For each 128 KiB-aligned extent chunk:
1. Full-extent write past current file size: skip old-extent lookup (nothing to free).
2. Partial write within file: fetch old extent, read + decrypt + decompress into scratch buffer, modify.
3. **Compress** plaintext into `comp_buf` (LZ4 by default). Keep the compressed form only if `csize < dlen`; otherwise fall back to raw.
4. **Encrypt** (if configured) the payload using `paddr` as the nonce prefix; output to `cipher_buf` with a 16-byte Poly1305 tag appended.
5. Allocate `ceil((clen + tag) / 4096)` blocks, write to disk.
6. Free old extent's blocks (if any).
7. Insert new 16-byte extent record in btree. `stm_extent_set` packs `clen` and `comp` into one 32-bit field.

Transform pipeline: `plaintext ── compress? ──► payload ── encrypt? ──► disk`

Uses reusable scratch buffers (`fs->extent_buf`, `fs->comp_buf`, `fs->cipher_buf`) — no per-extent malloc.

### 4.3 Read path (`stm_fs_read` → `extent_read_data`)

1. Clamp request against file size.
2. For each extent in range, look up the 16-byte record.
3. **Decrypt** (if encrypted) the `clen + tag` bytes from disk into a payload buffer.
4. **Decompress** (if `comp != NONE`) from the payload buffer into the final extent buffer.
5. Copy the relevant portion to the user's buffer.
6. Missing extents fill with zeros (sparse holes).

Zero-copy fast path: for uncompressed, unencrypted extents the on-disk bytes are read straight into the user-supplied buffer (no intermediate copy).

### 4.4 Compression policy

The filesystem's default algorithm (`fs->comp_algo`) is set at mount time — LZ4 when built with `STM_HAVE_LZ4`, otherwise `STM_COMP_NONE`. Per-extent, we attempt compression, measure, and only keep the compressed form if it's strictly smaller than the plaintext. This avoids pathological growth on incompressible data (random, already-compressed files) while still winning on text, code, and sparse-ish data.

The stored `comp` byte is persisted with the extent record, so readers always know how to decode — mixing compressed and uncompressed extents in one file is fine.

---

## 5. Block allocator

### 5.1 Structure

Per-block 32-bit refcount array (widened from 16-bit so volumes with very many snapshots sharing a root block don't saturate and mis-free). Values:
- `0` — free
- `1..0xFFFFFFFE` — in use (clamped to avoid sentinel collision)
- `0xFFFFFFFF` — `REFCOUNT_PENDING` (freed, not yet reusable)

The array costs 4 bytes per 4 KiB block — 1 MiB per 1 GiB of volume.

### 5.2 Allocation strategy

**Fast path**: forward scan from hint cursor for up to 4096 blocks. On success, mark used and advance hint. On end-of-volume, wrap to block 2 (skip superblocks).

**Slow path**: O(total) scan from block 0. Skipped if `free_count < count` (go straight to grow).

**Grow path**: extend the backing file by 12.5% of current size, clamped to [64 MiB, 1 GiB]. Uses `ftruncate`.

### 5.3 Deferred free

`stm_alloc_free` decrements refcount. On 0, sets `REFCOUNT_PENDING` and records in deferred list. Block becomes truly free only after `stm_alloc_commit`, which runs AFTER the superblock is durably on disk. This prevents reusing a block whose free hasn't been committed.

### 5.4 Mount-time reconstruction

`stm_alloc` is rebuilt on every mount by walking all live trees (main + snap tree + each snapshot's saved root) and incrementing refcounts via `stm_alloc_mark`.

---

## 6. Copy-on-write (COW)

### 6.1 Principle

Never overwrite live data. Every modification produces a new bptr; the old one is freed after the replacement is visible.

### 6.2 Write sequence

1. Encode node to scratch buffer.
2. Compress (optional, skip if no size win).
3. Allocate new blocks.
4. Encrypt (optional); nonce = paddr ‖ write_gen. See §9.3.
5. Compute xxHash3-128 csum over on-disk bytes.
6. Write to disk.
7. Populate new bptr; update parent pointer.
8. Call `free_old_bptr` with the **old bptr** (accurate csize from the old parent).

### 6.3 Critical bug-fix

An earlier version freed old blocks using the NEW node's compressed size — wrong because compression ratio varies between versions. Now `free_old_bptr` takes the old bptr directly. This was the root cause of encrypted-volume corruption after several copy-delete cycles.

---

## 7. Crash safety

### 7.1 Ping-pong superblocks

Two SB slots at block 0 and block 1. On mount, both are read, csum-verified, version-checked (only v2 accepted; non-v2 deterministically loses the tiebreak even at higher gen), and the higher-`ss_gen` valid slot wins. See §23 for the full mount selection policy.

### 7.2 The generation invariant

**Every crash-safety guarantee on encrypted volumes rests on one invariant:**

> At every observable on-disk state, `max(valid SB's ss_gen) > fs->gen` (where `fs->gen` is the write_gen that the session is currently encrypting under, i.e. the gen that would be used for the next ciphertext write).

The AEAD nonce is `(paddr ‖ write_gen)`. If two writes ever share that pair, XChaCha20 stream-cipher semantics leak `plaintext_1 XOR plaintext_2`. The invariant guarantees no two sessions can ever reuse a gen: the next session's `fs->gen` is read from the durable SB's `ss_gen`, and because disk `ss_gen` is always strictly greater than anything this session wrote under, the next session starts above every prior orphan gen.

Maintaining it is non-trivial. It is **not** true that `fs->gen` simply advances monotonically on disk — a crash between a flush and its SB commit would leave orphan ciphertexts at `fs->gen` while the SB still says the same `ss_gen` for the next mount to reuse. The invariant is maintained by three mechanisms working in concert:

1. **Mount-time gen bump** (encrypted volumes only): `stm_fs_open` writes an SB at `ss_gen = chosen_gen + 1` to the opposite slot + fsync, before returning. This establishes `disk ss_gen > fs->gen` *before* any session write can touch disk.

2. **Three-phase sync** (every successful sync):
   - **Phase 1 (reservation)**: write SB at `ss_gen = G+1` with the *pre-flush* root to the opposite slot, fsync. At this point no new ciphertexts at G have hit disk yet; if anything up to Phase 3's fsync fails, next mount reads G+1 and any orphans at G can't collide.
   - **Phase 2 (flush)**: tree flush at `write_gen = G`. Disk ss_gen is already G+1 (from Phase 1), so orphans at G are safe.
   - **Phase 3 (final)**: write SB at `ss_gen = G+2` with the *post-flush* root to the current slot, fsync. `fs->gen` advances to G+1. Strict inequality `disk ss_gen = G+2 > fs->gen = G+1` preserves the invariant for the next inter-sync window.
   - Torn-write on Phase 3: reservation at G+1 survives; mount picks it; next session writes at G+1 and doesn't collide with Phase 2 orphans at G.

3. **Rollback-bump before allocator swap**: `stm_snap_rollback` on encrypted volumes advances `fs->gen` by 1 and writes a bump SB (ss_gen = new_gen + 1) to the opposite slot **before** committing the new allocator swap. Without this, pre-rollback in-session orphans at old `fs->gen` would be marked FREE by the new allocator and could collide with post-rollback writes at the same gen. If the bump write fails, the old allocator still holds their refcounts — rollback is cleanly aborted.

The invariant also requires **counter-wraparound defense**: `ss_gen > UINT64_MAX - 2^32` is rejected at mount. Without that clamp, an adversarial SB pinned at `UINT64_MAX` would cause every mount to start at that gen, with mount-bump wrapping to 0 and subsequent writes colliding with the pinned-gen orphans.

### 7.3 Ordering of disk writes

```
stm_fs_sync(fs):
    gen_used     = fs->gen
    gen_reserve  = gen_used + 1
    gen_final    = gen_used + 2

    # Phase 1: reservation
    build_sb(ss_gen=gen_reserve, ss_root=stm_btree_root(tree))  # PRE-flush root
    write_sb(1 - fs->sb_slot)
    block_sync()                      ← crash boundary 1

    # Phase 2: flush
    stm_btree_flush(tree, gen_used)
    # snap_tree flush if present

    # Phase 3: final commit
    build_sb(ss_gen=gen_final, ss_root=stm_btree_root(tree))   # POST-flush root
    write_sb(fs->sb_slot)
    block_sync()                      ← crash boundary 2

    fs->gen = gen_used + 1            # advance by 1, not 2
    stm_alloc_commit()                # PENDING → free
```

On Darwin, `block_sync()` uses `fcntl(F_FULLFSYNC)` instead of `fsync()` — plain `fsync()` on macOS returns after writes reach the OS page cache but before the drive's volatile cache is flushed; `F_FULLFSYNC` forces a real disk-cache flush. On Linux we keep `fsync()` (which on ext4/xfs does issue the disk flush).

### 7.4 File locking

`flock(LOCK_EX | LOCK_NB)` on open prevents two processes from opening the same volume path. Released automatically on process exit (kernel handles even SIGKILL). One caveat: `flock` is per-open-file-description, so two processes opening two *hardlinks* to the same inode both acquire the lock. The file backend refuses to open any file with `st_nlink > 1` as a defense.

### 7.5 Recovery

Crash at any point during sync:
- **Before Phase 1 write**: no change; next mount picks the prior final. No orphans.
- **During Phase 1 (torn)**: opposite slot has garbage → csum fails. Mount picks the prior final. Same as above.
- **After Phase 1 but before Phase 3**: opposite slot has `(gen_reserve, pre-flush root)`. Mount picks it. Session's in-flight changes are lost; fs state reverts to pre-sync. Phase 2 orphans at `gen_used` are unreachable and safe (next session starts at `gen_reserve > gen_used`).
- **During Phase 3 (torn)**: current slot garbage. Mount falls back to reservation at `gen_reserve`. Same as above.
- **After Phase 3**: normal success.

In all cases: worst outcome is losing the current uncommitted transaction. No corruption. No nonce reuse. The allocator is rebuilt from scratch at next mount by walking the tree; orphans at any gen are correctly recognized as free and get a fresh gen on reallocation.

### 7.6 Wedged and read-only states

Two runtime `fs` flags protect invariants that can't be checked statically:

- **`fs->wedged`** — set when an internal failure (notably `stm_snap_rollback` reopen-original failures) leaves `fs->tree` NULL or otherwise unusable. Every public `stm_fs_*` and `stm_snap_*` API checks this via `STM_FS_GUARD_READ` / `STM_FS_GUARD_WRITE` and returns `-EIO`. Only `stm_fs_close` remains legal. Monotonic — once set, requires remount.

- **`fs->read_only`** — set by `stm_fs_open_ro`. Mutation APIs return `-EROFS`; read APIs proceed. `stratum check` uses this to inspect volumes without triggering the encrypted-mount gen bump, so it can run on degraded volumes. Callers of `stm_fs_open_ro` MUST NOT bypass the guards by reaching into `fs` internals — doing so on an encrypted volume produces orphan ciphertexts that violate the nonce invariant.

---

## 8. Filesystem layer

### 8.1 `struct stm_fs`

Contains: block device, btree, snap tree, generation counter, next-inode, sb_slot, encryption state, DEK, reusable scratch buffers (extent_buf, cipher_buf).

### 8.2 Inodes

Stored at `(ino, STM_KEY_INODE, 0)`. 88 bytes.

### 8.3 Dirents

FNV1a hash of name plus linear probing (up to 256 slots per name). Value = `[le64 child_ino][u8 dtype][name bytes]`.

### 8.4 Operations

- `stm_fs_create`: format volume, root inode (ino 1, mode 0755 | IFDIR).
- `stm_fs_open`: mount, decrypt DEK, open trees, rebuild allocator.
- `stm_fs_sync`: see §7.2.
- `stm_fs_mkdir` / `stm_fs_create_file`: allocate ino, insert inode, insert dirent.
- `stm_fs_unlink`: find dirent, delete dirent, decrement nlink; if 0, free all data extents + delete inode.
- `stm_fs_write` / `stm_fs_read`: see §4.

---

## 9. Encryption

### 9.1 Algorithm

**XChaCha20-Poly1305** via libsodium. Optional build dep (`STM_HAVE_CRYPTO`).

### 9.2 Key hierarchy

```
passphrase ──Argon2id(salt)──► KEK (32 B)
                                │
DEK (32 B random)               │ wrap
                                ▼
                          wrapped DEK (48 B) in ss_enc_wrapped_key
```

DEK is unwrapped on mount and used for all subsequent encrypt/decrypt.

Argon2id is parameterized at libsodium's `SENSITIVE` tier — `OPSLIMIT_SENSITIVE` (4 iterations) and `MEMLIMIT_SENSITIVE` (1 GiB). This is the data-at-rest tier: mount takes ~3-5 seconds on a modern laptop; the memory cost is what actually defeats GPU/ASIC brute force, since parallelism on those accelerators is limited by their (much smaller) RAM per compute unit. The cost is paid exactly once per mount, so the overhead is invisible to interactive use.

### 9.3 Nonce construction

Nonce (24 B) = `le64(paddr) ‖ le64(write_gen) ‖ 8 zero bytes`.

`write_gen` is the current-write sync generation:
- For data extents: `fs->gen` at the time of `extent_write_data`.
- For btree nodes: `tree->write_gen`, which every public btree entry point (`stm_btree_insert`, `stm_btree_delete`, `stm_btree_flush`) sets to its caller's gen before any writes fire. Critically, this is *not* the node's frozen creation gen (`n->gen`), which stays fixed for the node's lifetime and would cause nonce reuse on any COW-rewrite of the same paddr.

It is persisted alongside the ciphertext:
- Btree nodes store it in `bp_write_gen` of the parent's bptr.
- Data extents store it in `se_write_gen` of the extent record.

Why it matters: `paddr` alone is not unique across time. Under COW, a block may be freed and later re-allocated for a different piece of data; encrypting that new plaintext under `(DEK, nonce=paddr)` would reuse the same nonce with the same key, destroying confidentiality (XOR of the two ciphertexts = XOR of the two plaintexts — a classic stream-cipher catastrophe). Mixing `write_gen` into the nonce makes every re-use distinct, because `fs->gen` strictly increases across syncs — **but only if the disk generation counter stays strictly ahead of any gen ever used for ciphertext, across every mount boundary and every crash**. See §7.2 for the three-phase sync + mount-bump + rollback-bump machinery that maintains that strict inequality, and §23 for the full invariant statement.

### 9.4 AEAD integrity

Poly1305 tag (16 bytes) detects tampering and corruption. Decrypt fails with `-EIO` on any mismatch.

---

## 10. Compression

Two independent compression paths share the same codec layer (`src/compress/compress.c` — LZ4 or ZSTD, selected by a one-byte `STM_COMP_*` tag).

### 10.1 Per-node compression (btree)

Each Bε-tree node is compressed on write, recorded in `bp_comp` / `bp_csize` / `bp_lsize` of its parent pointer. Skipped if compressed size ≥ original — the raw form is stored.

### 10.2 Per-extent compression (data)

File-data extents go through the same pipeline: every extent is trial-compressed on write, kept compressed only if it shrinks. The algorithm and stored length are persisted alongside the extent record (`se_clen_and_comp`). Mixed compression within a single file is fine — each extent decodes independently.

Default is LZ4 (fast, good-enough ratio). ZSTD is available when built with `STM_HAVE_ZSTD` and can be selected at mkfs time.

### 10.3 Per-volume selection

The algorithm is chosen at `mkfs` and persisted in `ss_comp_algo` in the superblock:

```
stratum mkfs <path> <size> [--compress lz4|zstd|none]
```

Default: `lz4` when the build has LZ4, else `none`. The choice is stable for the life of the volume — `stm_fs_open` reads `ss_comp_algo` and refuses to mount if the codec isn't compiled into the current binary (otherwise existing compressed extents would be unreadable).

Because every `stm_extent` carries its own `comp` byte, a volume that is later "re-created" with a different default still reads cleanly — each extent decodes via its own persisted algo.

### 10.4 Observed results

On a volume with 45 MiB of repeating-text payload:

| mkfs flag | Blocks used | Ratio |
| --- | --- | --- |
| `--compress none` | 10993 (~43 MiB) | 1.0× |
| `--compress lz4`  | 347 (~1.4 MiB)   | ~31× |
| `--compress zstd` | 347 (~1.4 MiB)   | ~31× |

Incompressible data (random bytes, pre-compressed archives) pays a few microseconds per extent for the trial-compress, then falls back to raw storage. The `se_clen == se_dlen`, `comp == NONE` invariant is verified by `stratum check`.

---

## 11. Integrity checksums

xxHash3-128, zero-padded to 32 bytes. Two levels:

- **bp_csum**: covers on-disk bytes of a btree node (post-compress, post-encrypt). Verified BEFORE decryption — detects corruption cheaply.
- **ss_csum**: covers the 512-byte superblock with csum field zeroed. Invalid superblock is rejected during mount.

Backward compatible: all-zero csum passes verification (for old volumes without xxHash).

---

## 12. Snapshots

### 12.1 Model

A snapshot is a persisted `stm_bptr` pointing at the root of the main tree at snapshot time. Reads through that root observe the tree as it was. Writes go to the current tree; COW + refcounting ensures snapshot blocks aren't freed.

### 12.2 Operations

- **Create**: flush current tree, save root bptr in snap tree, walk all blocks and `stm_alloc_ref` each one.
- **List**: scan snap tree for all `STM_KEY_SNAP` entries.
- **Rollback**: close current tree, reopen from snapshot root, **rebuild allocator from scratch** (critical for correctness).
- **Delete**: walk snapshotted tree, `stm_alloc_free` each block, delete descriptor.

### 12.3 Exposed interfaces

- **C API**: `stm_snap_create/list/delete/rollback` in `src/snap/snap.c`.
- **CLI**: `stratum snap <vol> <create|list|delete|rollback> [name|id]`.
- **9P extensions** (types 128-135): Tsnap_create, Tsnap_list, Tsnap_delete, Tsnap_rollback.
- **TUI**: F9 or `s` key opens snapshot dialog (list, create, rollback, delete).
- **TUI CLI**: `stratum-tui cli <vol> snap <create|list|delete|rollback> [name|id]`.

### 12.4 9P extension wire format

```
Tsnap_create:   size[4] type[1] tag[2] name[s]
Rsnap_create:   size[4] type[1] tag[2] id[8]

Tsnap_list:     size[4] type[1] tag[2]
Rsnap_list:     size[4] type[1] tag[2] count[2] { id[8] gen[8] name[s] } * count

Tsnap_delete:   size[4] type[1] tag[2] id[8]
Rsnap_delete:   size[4] type[1] tag[2]

Tsnap_rollback: size[4] type[1] tag[2] id[8]
Rsnap_rollback: size[4] type[1] tag[2]
```

All snap operations trigger `stm_fs_sync` on the server side to ensure durability.

---

## 13. 9P protocol server

### 13.1 Supported messages

Standard 9P2000: Tversion, Tattach, Twalk, Topen, Tcreate, Tread, Twrite, Tclunk, Tremove, Tstat, Tflush.

**Stratum extensions** (types 128-135): Tsnap_create/list/delete/rollback.

### 13.2 Key features

- **msize**: 1 MiB default.
- **Fid table**: 256 linear-scan entries.
- **Partial walks**: rejected when `newfid != fid` to prevent fid confusion.
- **h_clunk**: syncs fs if fid had writes.
- **h_remove**: unlinks + syncs to commit freed blocks.
- **Readdir cache**: per-fid cached stat listing, avoiding re-scan on each 9P read.

### 13.3 Transport

- Unix socket: `unix:/path/to.sock`
- TCP: `tcp:host:port`

---

## 14. CLI (stratum binary)

```
stratum mkfs  <path> <size>  [--pass <p>|--pass-stdin] [--compress lz4|zstd|none]
stratum serve <path>          [--pass <p>|--pass-stdin] [--listen <addr>]
stratum info  <path>          [--pass <p>|--pass-stdin]
stratum check <path>          [--pass <p>|--pass-stdin] [--verbose]
stratum scrub <path>          [--pass <p>|--pass-stdin] [--verbose]
stratum snap  <path> <create|list|delete|rollback> [name|id]
                               [--pass <p>|--pass-stdin]
```

### 14.1 Password handling

- `--pass <value>`: password on command line (visible in `ps`).
- `--pass-stdin`: read one line from stdin (not visible). Used by TUI to pipe password securely.

### 14.2 `check` command (fsck — structural)

1. Read both superblocks, verify magic + csum.
2. `stm_fs_open_ro` — fails on any bptr corruption.
3. Walk every btree node + every leaf entry + every INSERT message in internal nodes.
4. Validate: csize > 0, paddr within device, data values are 24-byte extent records with valid paddr/dlen.
5. Verify root inode exists.
6. Refcount reconciliation: mark every reachable block and cross-check against the rebuilt allocator.
7. Summary: node count, entry count, inode count, extent count + bytes, free blocks.

Fast. Skips extent payload bytes — does not catch bitrot in file data.

### 14.3 `scrub` command (deep integrity)

Online integrity sweep. Reads every byte of every extent and forces AEAD tag or xxHash3 csum verification on the read path.

1. `stm_fs_open_ro` (skip mount-bump — does not modify the volume).
2. Walk main tree via `stm_btree_walk_entries`: each node visit forces `stm_btree_read_node` → csum + AEAD verify; each DATA leaf entry triggers a full `extent_read_data` → AEAD tag verify (encrypted) or bounds/decompress verify (unencrypted).
3. Walk snap tree (descriptors + name index).
4. For each saved snapshot descriptor, walk its subtree.
5. Progress on stderr every ~1s: nodes, extents, bytes, errors. Summary on stdout.

Exit code: `0` clean, `1` errors found, `2` couldn't run (bad path, bad passphrase, unmountable volume — use `check` for structural diagnosis in that case).

On **encrypted volumes** scrub is airtight — every extent carries a Poly1305 tag, so any bitrot surfaces as `-EIO` on first read. On **unencrypted volumes** today, extent payload bytes have no per-extent integrity field; scrub exercises btree-node csums but cannot verify extent data. SOTA #7 (per-extent AEAD on unencrypted volumes) closes this gap.

Complements `check`:
- `check` = metadata integrity (tree shape, refcounts). Fast. Run on every mount / after suspected metadata corruption.
- `scrub` = data integrity (every stored byte decodes). Slow. Run periodically (cron), before backups, after hardware trouble.

---

## 15. TUI (stratum-tui)

### 15.1 Architecture

Built on ratatui + crossterm + tui-textarea. Dual-pane FAR/Norton Commander style.

### 15.2 Key bindings

| Key | Action |
| --- | --- |
| F2 | Mount Stratum volume |
| Shift+F2 | Mount host filesystem |
| Alt+Shift+F2 | Connect raw 9P |
| F3 | View file (read-only editor) |
| F4 | Edit file |
| F5 | Copy to other pane |
| F7 | Mkdir |
| F8 | Delete (cursor or selected) |
| F9 or `s` | Snapshot dialog |
| F10 or `q` | Quit |
| Space | Multi-select (moves cursor down) |
| Tab | Switch pane |

### 15.3 Copy engine

Streaming with persistent read/write handles, 1 MiB chunks, 200 ms batching per tick. Progress dialog shows aggregate stats, throughput chart, ETA. Multi-select batches all files with persistent stats. Directory copy is recursive.

### 15.4 Modal editor

Helix-style: Normal, Insert, Visual, Command modes. System clipboard via pbcopy/pbpaste. Max file size 2 MiB.

### 15.5 Snapshot dialog

F9 or `s` opens a modal dialog listing all snapshots of the active panel's volume. Keybindings:
- `N` or `c`: create new snapshot (prompts for name)
- `R` or Enter: rollback to selected
- `D` or Delete: delete selected
- `↑/↓` or `j/k`: navigate
- `Esc`: close

Works only on stratum-mounted panels.

### 15.6 CLI mode

`stratum-tui cli <volume> <command>`:
- `ls [path]`
- `mkdir <name>`
- `rm <name>`
- `cp-in <host-path> [dest-name]`
- `cp-out <stratum-name> <host-path>`
- `snap create <name>` / `snap list` / `snap delete <id>` / `snap rollback <id>`

---

## 16. FUSE backend (stratum-fuse)

SOTA #1. A userspace FUSE daemon that serves a Stratum volume at a POSIX mount point. Every Unix tool (`ls`, `cat`, `vim`, `grep`, `rsync`, `git`, `tar`, `find`, `rm`, `cp`) works against a Stratum volume as an ordinary filesystem. Complements the 9P server — same `stm_fs_*` backend, different frontend.

### 16.1 Architecture

```
user process   (ls / cat / vim / rsync / ...)
     │ POSIX syscall
     ▼
VFS  (kernel)
     │
FUSE kernel module (fuse.ko on Linux, macFUSE kext on macOS)
     │ /dev/fuse
     ▼
stratum-fuse daemon (C, linked with libfuse3 + stratum-lib)
     │ direct call
     ▼
stm_fs_* API  →  Bε-tree  →  block device  (same backend 9P uses)
```

**Direct link to stratum-lib**, not IPC. Every FUSE callback is a thin wrapper over the corresponding `stm_fs_*` function. Inode numbers are passed through unchanged — `fuse_ino_t` is `uint64_t`, `STM_ROOT_INO` and `FUSE_ROOT_ID` both equal 1.

### 16.2 Operation mapping

| FUSE op | stm_fs_* | Status |
|---|---|---|
| `lookup(parent, name)` | `stm_fs_lookup` + `stm_fs_stat` | wired |
| `getattr(ino)` | `stm_fs_stat` | wired |
| `setattr(ino, attr, to_set)` | `stm_fs_chmod` / `_chown` / `_utimes` / `_truncate` | wired (SOTA #5 Group A) |
| `mkdir(parent, name, mode)` | `stm_fs_mkdir` + `stm_fs_chown` (from fuse_req_ctx) | wired |
| `rmdir(parent, name)` | `stm_fs_unlink` | wired (checks empty via -ENOTEMPTY) |
| `create(parent, name, mode)` | `stm_fs_create_file` + `stm_fs_chown` (from fuse_req_ctx) | wired |
| `unlink(parent, name)` | `stm_fs_unlink` | wired |
| `open(ino, flags)` | noop | wired (no per-handle state) |
| `read(ino, size, off)` | `stm_fs_read` | wired |
| `write(ino, buf, size, off)` | `stm_fs_write` | wired |
| `flush(ino, fi)` | noop | wired (no per-close sync; avoid spam) |
| `release(ino, fi)` | `stm_fs_sync` | wired (sync on last close, mirrors 9P h_clunk) |
| `fsync(ino, datasync)` | `stm_fs_sync` | wired |
| `readdir(ino, size, off)` | `stm_fs_readdir` | wired (via `fuse_add_direntry`) |
| `statfs(ino)` | placeholder | wired (generic values until SOTA #2) |
| `rename(parent, name, newparent, newname)` | `stm_fs_rename` | wired (SOTA #5 Group B) |
| `setxattr` / `getxattr` / `listxattr` / `removexattr` | `stm_fs_xattr_{set,get,list,remove}` | wired (SOTA #5 Group C) |
| `link(ino, newparent, newname)` | `stm_fs_link` | wired (SOTA #5 Group D) |
| `symlink`, `readlink`, `mknod`, `access` | — | ENOSYS (symlinks + special files out of roadmap scope) |

**`setattr` dispatch (SOTA #5 Group A)**: the FUSE layer inspects the `to_set` bitmask and routes each field independently to the corresponding stm_fs_* mutation. `FUSE_SET_ATTR_MODE` → `stm_fs_chmod`, `UID`/`GID` → `stm_fs_chown` (with the other field passed as `(uint32_t)-1` to mean "don't change"), `ATIME`/`MTIME` (plain or `_NOW`) → `stm_fs_utimes`, `SIZE` → `stm_fs_truncate`. After all mutations succeed, getattr is re-run and the refreshed attrs are returned so FUSE's kernel cache stays consistent.

**Creation-time ownership**: `ll_create` and `ll_mkdir` call `stm_fs_chown(uid, gid)` with the values from `fuse_req_ctx()` immediately after create — so a user mounting the volume and touching a file sees the file owned by them (not uid 0). Pre-Group-A behavior returned `getuid()` from `fill_attr` regardless of the stored inode values.

### 16.3 Concurrency

**Single-threaded event loop** (`fuse_session_loop`, not `_mt`). `stm_fs_*` is not thread-safe — two concurrent inserts would race in the btree message buffer. Single-threaded is both correct and simpler. Multi-threaded FUSE would need either a global mutex around every `stm_fs_*` call or fine-grained locking inside the btree; the latter is SOTA #14 territory.

### 16.4 Lifecycle

```
stratum-fuse <volume> <mountpoint>
    [--pass <p>|--pass-stdin]  passphrase for encrypted volumes
    [-f]                         foreground (useful for debugging)
    [-d]                         debug (verbose libfuse trace; implies -f)
```

Flow:
1. Parse args. Read passphrase if requested.
2. `stm_fs_open` the volume.
3. `fuse_session_new` with the callback table.
4. `fuse_set_signal_handlers` — Ctrl-C / SIGTERM exit the loop cleanly.
5. `fuse_session_mount` — kernel attaches `/dev/fuse` to the mountpoint.
6. `fuse_daemonize(0)` unless `-f` / `-d` — fork, detach from terminal.
7. `fuse_session_loop` — process requests until a signal breaks the loop.
8. `fuse_session_unmount` + `fuse_session_destroy` + `stm_fs_close`.

**Unmount**:
- Linux: `fusermount -u <mountpoint>` (or kill the daemon and the kernel unmounts on FUSE disconnect).
- macOS: `umount <mountpoint>` (macFUSE doesn't ship `fusermount`).

Abnormal termination (SIGKILL, panic) leaves a stale mount; the user clears it with the same commands.

### 16.5 Security

- **Per-user mount**: no `-o allow_other`. Only the user who ran `stratum-fuse` can see the mount.
- **uid/gid**: FUSE passes caller uid/gid via `fuse_req_ctx()`. Stratum's inode struct has `si_uid` / `si_gid` fields but they aren't enforced yet (SOTA #5 POSIX completion). Every op is effectively attributed to the mounting user.
- **Inherit from the volume's security story**: on encrypted volumes, the FUSE daemon holds the DEK in memory for the lifetime of the process; close via signal wipes it (via `stm_fs_close` → `memset(fs->dek, 0, ...)`).

### 16.6 Performance

FUSE introduces ~20-50 μs overhead per op (two kernel↔userspace transitions) vs direct `stm_fs_*` calls. The recently-landed btree node LRU cache (SOTA #3) eliminates redundant tree walks across successive ops, so the FUSE path doesn't compound disk-read overhead.

Expect roughly comparable throughput to the 9P path for streaming I/O, slightly faster for metadata-chatty workloads (`ls -laR`, `find`) because FUSE uses in-kernel attribute caching (1-second timeout by default — safe because the daemon is the only writer).

### 16.7 Platform requirements

| Platform | Requirement | Install |
|---|---|---|
| Linux | libfuse3 ≥ 3.x headers + runtime | `apt install libfuse3-dev` / `dnf install fuse3-devel` |
| macOS | macFUSE (must be kext-approved in System Settings → Privacy & Security before first mount) | macFUSE installer from <https://macfuse.github.io/> |

If libfuse3 isn't present at configure time, CMake prints `"libfuse3 not found: stratum-fuse will be skipped"` and the rest of the build proceeds. The 9P server + TUI remain fully functional without FUSE.

### 16.8 Build-time notes

- macFUSE's `fuse_lowlevel.h` uses `typeof` (a GNU extension) for its Darwin-extended op signatures. The `stratum-fuse` CMake target overrides `-std=c99` to `-std=gnu99` via `target_compile_options`.
- We force `FUSE_DARWIN_ENABLE_EXTENSIONS=0` so the callback signatures match the vanilla Linux libfuse3 API on both platforms. Without this, macFUSE's setattr would take `struct fuse_darwin_attr *` instead of `struct stat *`.

---

## 17. Build system

### 17.1 CMake (C)

```
cmake -B build -DCMAKE_BUILD_TYPE=Release .
cmake --build build
```

Optional dependencies (each enables a feature):
- LZ4 / ZSTD → compression
- libsodium → encryption
- xxhash → checksums
- libfuse3 → `stratum-fuse` binary (§16)

### 17.2 Cargo (Rust TUI)

```
cd tui && cargo build --release
```

---

## 18. Testing

- **11 C test suites** in `tests/`, covering types, keys, blocks, nodes, btree, fs (including 10-cycle copy-delete stress tests both plain and encrypted), compression, crypto, snapshots, 9P, allocator.
- **Rust integration tests** in `tui/tests/integration.rs`: 10 scenarios via CLI (small/large files, overwrite, sparse, binary integrity, autogrow, 200 small files, performance scaling).
- **Crash-injection fuzzer** in `tui/tests/fuzz.rs` (SOTA #4): seeded-random operation sequences against a live `stratum serve`, SIGKILL at random mid-sequence points, remount + `check` + `scrub` + model verification per iteration. Default `cargo test` budget runs 3 iterations × 20 ops (~350 ms); stress campaigns via `FUZZ_ITERS=1000 FUZZ_OPS=60 cargo test --test fuzz --release` cover 60 000 ops + 1 000 crash boundaries in ~3 minutes. Every audit-derived invariant (nonce uniqueness, two-phase sync, wedged/RO containment, counter clamps) is re-validated in every iteration.

---

## 19. Performance characteristics

- CLI: 300-500 MB/s on modern SSD.
- TUI: 150-200 MB/s (UI overhead).

Key optimizations applied (git history):
- Extent-based storage (vs inline btree values)
- Per-extent LZ4 compression (~30× on compressible data, free on random)
- Single fsync per sync (not one per tree)
- pread/pwrite (not stdio)
- Reusable scratch buffers (extent_buf, comp_buf, cipher_buf)
- Drain-free scan (no full tree drain per readdir)
- Readdir result caching in 9P server
- Allocator hint wraparound
- Skip lookup on growing writes

---

## 20. Edge cases and gotchas

- **128 KiB extent + AEAD tag**: encrypted extent uses 33 blocks (128 KiB + 16 B tag rounds up).
- **Partial 9P walks**: server rejects when `newfid != fid`; client also guards.
- **Dirent collisions**: FNV1a + 256-slot linear probe. No tombstones — deletion leaves a hole that subsequent lookups respect.
- **Refcount clamp at 0xFFFFFFFE**: prevents collision with `REFCOUNT_PENDING = 0xFFFFFFFF`.
- **Deferred free under OOM**: if the deferred list can't grow, free silently reverts the refcount. Block is leaked until next mount's tree-walk rebuild.

---

## 21. Known limitations / future work

1. **No intermediate commits during long writes**. A 50 GB copy loses everything on crash before sync. (Attempted; reverted due to encryption corruption.)
2. **No node cache**. Every `stm_btree_read_node` does full malloc + I/O + decrypt + decompress + decode.
3. **No defragmentation**.
4. **Allocator state not persisted**. Rebuilt via tree walk on mount (O(total nodes + extents)).
5. **No hard links, symlinks, xattrs, rename, chown, utime**.
6. ~~**No FUSE / kernel mount**. 9P only.~~ **Addressed (§16)** — `stratum-fuse` provides a POSIX mount point via libfuse3 / macFUSE.
7. **No CRC on extent data independent of AEAD**. Unencrypted volumes have no integrity check on data.

---

## 22. Glossary

| Term | Meaning |
| --- | --- |
| **AEAD** | Authenticated Encryption with Associated Data |
| **bptr** | Block pointer — 57-byte on-disk struct |
| **Bε-tree** | B-tree with message buffer in internal nodes |
| **COW** | Copy-on-write |
| **csum** | Checksum (xxHash3-128 zero-padded to 32 bytes) |
| **DEK** | Data Encryption Key (32 bytes, per-volume) |
| **Deferred free** | Refcount hit 0 but block not yet reusable |
| **Dirent** | Directory entry |
| **Extent** | 128 KiB-aligned run of disk blocks for file data |
| **fid** | 9P file id handle |
| **flock** | Advisory OS file lock |
| **gen** | Generation number (monotonic per-sync) |
| **KEK** | Key Encryption Key (derived from passphrase) |
| **Magic** | `0x004d555441525453` = "STRATUM\0" |
| **msize** | 9P maximum message size (1 MiB default) |
| **nonce** | XChaCha20 nonce (24 B; Stratum uses paddr LE ‖ write_gen LE ‖ zeros) |
| **paddr** | Physical byte address on device |
| **PENDING** | Refcount sentinel 0xFFFFFFFF for freed-but-not-committed |
| **QID** | 9P unique-id tuple |
| **Refcount** | Per-block reference count for snapshot sharing |
| **Scratch buffer** | Reusable per-fs buffer for extent I/O |
| **Sync** | Full checkpoint (flush trees + write superblock + fsync + commit) |
| **Tag** | Poly1305 MAC (16 bytes) |
| **Wedged** | fs-level flag set when internal failure leaves `fs->tree` unusable; public APIs reject until close |

---

## 23. Soundness invariants

This section is the **contract** that future changes must not break. Each invariant below has a history — every one was discovered by an adversarial audit (R0–R14, commits `bb39db8` → `405c4fb`, ~60 corruption-class fixes) — and each has at least one test in `tests/` that fails without its fix. Modifying any code path listed under "enforced at" triggers a fresh audit round before merge (see `CLAUDE.md`).

### 22.1 AEAD nonce uniqueness

**Invariant**: for every ciphertext ever written to disk under the current DEK, the pair `(paddr, write_gen)` is globally unique across the volume's lifetime.

Enforced at:
- `src/crypto/crypto.c::build_nonce` (nonce = `le64(paddr) ‖ le64(write_gen) ‖ zeros`).
- `src/btree/btree.c::stm_btree_write_node` uses `tree->write_gen`, set by every public entry point (`stm_btree_insert/delete/flush`) before any disk write. Not the frozen `n->gen`.
- `src/fs/fs.c::extent_write_data` uses `fs->gen`.

Depends on the generation invariant below.

### 22.1.1 AEAD associated data (ss_version ≥ 2)

**Invariant**: every ciphertext is produced with a context-specific AD struct bound into its tag. Extents bind `(magic=EXTD, version=1, ino, offset)`; btree nodes bind `(magic=BTND, version=1, tree_id)`. Decrypt MUST pass byte-identical AD, or AEAD fails.

Enforced at:
- `src/crypto/crypto.c::stm_crypto_{encrypt,decrypt}` — AD threaded into `crypto_aead_xchacha20poly1305_ietf_{encrypt,decrypt}`.
- `src/fs/fs.c::extent_write_data` / `extent_read_data` construct `stm_ad_extent` from `(ino, offset)` at every call site. `stm_fs_truncate`'s straddle RMW passes `(ino, align)` because that's the extent key.
- `src/btree/btree.c::stm_btree_{read,write}_node` construct `stm_ad_node` from `tree->tree_id`. `tree_id` is set on tree creation by `stm_btree_set_id` (main-format path) or `stm_fs_configure_tree` (every mount / snap / rollback path; snapshot subtrees walked via the main tree inherit `STM_TREE_ID_MAIN`).
- `src/cmd/check.c::probe_bptr` and `walk_ctx.tree_id` — set to MAIN / SNAP / MAIN-for-saved-subtrees around each walk phase.
- `src/cmd/scrub.c::visit_entry` passes `(kc.ino, kc.offset)` through `extent_read_data`.

Why: paddr+gen uniqueness alone doesn't stop an attacker with raw-disk write access from copying an extent's ciphertext to a different `(ino, offset)` btree key (the key is stored in a separately-encrypted btree node, but an attacker with key material could produce both swaps; more realistically, an attacker without the DEK can still tamper at the btree-value level if AD is absent — AEAD accepts the cipher as long as paddr+gen match, oblivious to location). Binding the location into AD fails AEAD the instant the read-side AD disagrees.

Without this, extent-swap / cross-tree node-swap go undetected by the crypto layer; only downstream sanity checks would catch them, and most plausibly mis-associated data reads succeed with wrong content. Rejected at mount: any `ss_version != 2` SB is refused with `-ENOTSUP`; see regression `test_fs_rejects_ss_version_1`.

### 22.1.2 Tree identity binding

**Invariant**: every `struct stm_btree` has a `tree_id` set at configure time (`STM_TREE_ID_MAIN` = 1 for main tree, `STM_TREE_ID_SNAP` = 2 for snap tree, `STM_TREE_ID_NONE` = 0 for unscoped unit-test trees). Every node encrypt/decrypt binds that id into AD. Tests that open a btree without `stm_fs_configure_tree` get id=0 (unscoped) — fine because those tests don't encrypt.

Enforced at:
- `include/stratum/btree.h` declares `stm_btree_set_id`.
- `src/fs/fs.c::stm_fs_create` (format path) calls `stm_btree_set_id(tree, STM_TREE_ID_MAIN)` before first write.
- `src/fs/fs_internal.h::stm_fs_configure_tree` takes a `tree_id` parameter and calls `stm_btree_set_id` first — before `stm_btree_set_crypto`, so the id is in place before any encrypted write can occur.
- All call sites (mount main, mount snap, ensure_snap_tree, rollback reopen, rollback failure-path reopen) pass an explicit id.

Without this, a node written under tree_id=MAIN and later referenced (via parent bptr rewrite) by code that reads it under tree_id=SNAP (or vice versa) would fail AEAD — catching the attack cryptographically. The tree_id is itself not secret (anyone can guess 1 or 2), but it's an invariant that the code at write and read agrees on; any refactor that changes which tree wrote a node MUST propagate the matching tree_id to the reader.

### 22.2 Generation invariant

**Invariant**: at every observable on-disk state, `max(valid SB ss_gen) > fs->gen`. The strict inequality must hold across: mount → first write, every inter-sync window, every sync phase transition, every crash boundary, every rollback.

Enforced at:
- `src/fs/fs.c::stm_fs_open_impl` — mount-time gen bump on encrypted volumes (writes `ss_gen = fs->gen + 1` to opposite slot + fsync before returning).
- `src/fs/fs.c::stm_fs_sync` — three-phase commit (Phase 1 reservation at G+1, Phase 2 flush at G, Phase 3 final at G+2, then `fs->gen = G+1`).
- `src/snap/snap.c::stm_snap_rollback` — rollback-bump BEFORE allocator swap; revert on bump failure is clean because `old_alloc` still holds pre-rollback refcounts.

See §7.2 for the full argument. Regression tests: `test_fs_sync_two_phase_gen_invariant`, `test_fs_mount_bump_encrypted`, `test_snap_rollback_bumps_gen_encrypted`.

### 22.3 Counter wraparound rejection

**Invariant**: `ss_gen`, `ss_next_ino`, `ss_next_snap_id` are each `≤ UINT64_MAX - 2³²` on a valid volume. Mount rejects anything above that with `-ENOTSUP`.

Enforced at: `src/fs/fs.c::stm_fs_open_impl` post-SB-parse clamps. Walk-side guards in `mark_extent_entry` refuse on-disk INODE/SNAP keys near the cliff. `alloc_ino` defensively skips 0 and `STM_ROOT_INO`.

Without this, an adversarial SB (plaintext + unkeyed xxHash3 csum) could pin `fs->gen` at `UINT64_MAX` across mounts, causing mount-bump to wrap and next-session writes to collide with pinned-gen orphans.

### 22.4 Walk-derived counter clamps

**Invariant**: at end of mount, `fs->next_ino > max_ino_ever_allocated_in_any_tree` and `fs->next_snap_id > max_snap_id_ever_created`.

Enforced at: `mark_extent_entry` raises `fs->next_ino` / `fs->next_snap_id` from every INODE / SNAP key observed during the mount-time tree walk (main tree, snap tree, every saved snapshot's tree).

Without this, an adversarial `ss_next_ino = K` (where K is any live inode) causes the next create to alias K — overwriting its inode record and inheriting its extents.

### 22.5 Extent write ordering

**Invariant**: on `stm_fs_write`, the btree record for a new extent lands before the old extent's blocks are freed. On insert failure, the new extent's blocks are reclaimed.

Enforced at: `src/fs/fs.c::stm_fs_write` (`extent_write_data` → `stm_btree_insert` → `extent_free_blocks(old)`; on insert failure: `extent_free_blocks(new)`).

Without this, `-ENOMEM` mid-write silently loses data: file's btree record still points at `old_ext`, but `old_ext`'s blocks are PENDING → freed → reallocated at next alloc → next read gets garbage or AEAD tag mismatch.

### 22.6 Extent scratch-buffer hygiene

**Invariant**: on partial-extent read-modify-write, `fs->extent_buf` tail is zeroed after the old extent's plaintext lands, so no residue from a prior extent operation is encrypted into the new ciphertext.

Enforced at: `src/fs/fs.c::stm_fs_write`, after `extent_read_data` in the `had_old` branch: `memset(ebuf + old_dlen, 0, STM_EXTENT_SIZE - old_dlen)`.

Without this, on encrypted volumes, one file's plaintext leaks into another file's encrypted extent when their write offsets and extent lifetimes interleave just so. Regression test: `test_fs_write_gap_is_zeroed*`.

### 22.7 Wedged / read-only runtime containment

**Invariant**: once `fs->wedged` is set, every public `stm_fs_*` / `stm_snap_*` API returns `-EIO` (or in `stm_fs_open_ro`'s case, `-EROFS` for mutations). The fs is only legal to `stm_fs_close` from that point.

Enforced at: top of every public API in `fs.c` and `snap.c` via `STM_FS_GUARD_READ` / `STM_FS_GUARD_WRITE` / `STM_SNAP_GUARD_*` macros.

Without this, `stm_snap_rollback` failure paths leave `fs->tree = NULL` and the next op dereferences NULL.

### 22.8 Superblock tiebreak

**Invariant**: mount picks the highest-gen valid SB whose `ss_version == 2`. If only one slot is v2, it wins regardless of gen. If neither is v2, mount fails with `-ENOTSUP`. (As of Phase D, v2 is current; v1 volumes — no AEAD AD binding — must be recreated.)

Enforced at: `src/fs/fs.c::stm_fs_open_impl` SB selection block.

Without this, an adversarial one-byte write (`ss_version = 3` + recomputed xxHash + bumped gen) wedges mount for a volume whose other slot is still legitimate.

### 22.9 9P wire validation

**Invariant**: every handler validates its body against `body_len` before reading fixed offsets. `gstr` bounds-checks against `end`. `h_read` and `h_write` clamp count against `s->msize - P9_HDR_SIZE - 4` in both file and directory branches. `s->msize` is clamped to `[P9_MSIZE_MIN=256, P9_MSIZE_DEFAULT]` in `h_version`.

Enforced at: `src/p9/p9.c::stm_9p_handle` and every handler.

Without this, malformed wire inputs cause heap OOB writes, heap OOB reads encoded into the volume (exposing server heap as file content on encrypted volumes), or remote DoS via segfault on unauthenticated 9P.

### 22.10 Fid lifecycle

**Invariant**: every allocated fid is freed on every exit path of its creating handler (including error paths). `dir_cache` is invalidated when a fid's ino changes (h_walk, h_create) or when a directory is mutated through any other fid (h_create, h_remove, snap ops). Duplicate `fid_alloc` on an already-active fid fails.

Enforced at: `src/p9/p9.c::fid_alloc`, `fid_free`, `fid_cache_drop`, `invalidate_dir_caches`, `invalidate_all_dir_caches`. `stm_9p_destroy` frees every fid's `dir_cache` on client disconnect.

Without this, long-running servers leak memory under misbehaving clients; fid-table exhaustion causes DoS; stale readdir caches serve wrong directory state to clients.
