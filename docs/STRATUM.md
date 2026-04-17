# Stratum — The Definitive Technical Reference

**Version**: repository state at commit `3998786` (P2 perf: allocator hint wrap + readdir cache), updated through snapshot/CLI 9P extensions.
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
16. [Build system](#16-build-system)
17. [Testing](#17-testing)
18. [Performance characteristics](#18-performance-characteristics)
19. [Edge cases and gotchas](#19-edge-cases-and-gotchas)
20. [Known limitations / future work](#20-known-limitations--future-work)
21. [Glossary](#21-glossary)

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
- **Kernel FUSE mount** — there is no FUSE bridge. Applications must talk 9P.

### 1.3 Relation to other COW filesystems

| Feature | Stratum | btrfs | ZFS | APFS |
| --- | --- | --- | --- | --- |
| Data structure | **Bε-tree** | B-tree | object set + tree | B-tree |
| Block integrity | xxHash3-128 | CRC32C | fletcher2/4 / SHA-256 | none |
| Encryption | per-block XChaCha20-Poly1305 (nonce = paddr) | via dm-crypt | AES-CCM/GCM | AES-XTS |
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
8       4      le32    ss_version        currently 1
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
8       8      le64    bp_laddr          logical address (reserved)
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

### 2.7 `struct stm_extent` (16 bytes)

```
0       8      le64    se_paddr           on-disk address of extent data
8       4      le32    se_dlen            logical (uncompressed) data length
12      4      le32    se_clen_and_comp   low 24 bits: stored disk length (pre-AEAD-tag)
                                          high 8 bits: compression algo (STM_COMP_*)
```

Stored as the btree value for `STM_KEY_DATA` keys.

The compression algo is packed into the high byte of `se_clen_and_comp`; the low 24 bits hold the stored length on disk (covers up to 16 MiB, more than enough for the 128 KiB max extent). If compression did not shrink the data, the raw form is stored and `se_clen == se_dlen`, `comp == STM_COMP_NONE`.

Access via helpers:

```c
uint32_t stm_extent_clen(const struct stm_extent *e);
uint8_t  stm_extent_comp(const struct stm_extent *e);
void     stm_extent_set(struct stm_extent *e, uint64_t paddr,
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

Per-block 16-bit refcount array. Values:
- `0` — free
- `1..0xFFFE` — in use (clamped to avoid sentinel collision)
- `0xFFFF` — `REFCOUNT_PENDING` (freed, not yet reusable)

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
4. Encrypt (optional); nonce = paddr.
5. Compute xxHash3-128 csum over on-disk bytes.
6. Write to disk.
7. Populate new bptr; update parent pointer.
8. Call `free_old_bptr` with the **old bptr** (accurate csize from the old parent).

### 6.3 Critical bug-fix

An earlier version freed old blocks using the NEW node's compressed size — wrong because compression ratio varies between versions. Now `free_old_bptr` takes the old bptr directly. This was the root cause of encrypted-volume corruption after several copy-delete cycles.

---

## 7. Crash safety

### 7.1 Ping-pong superblocks

Two slots (blocks 0 and 1). On each sync, write to the slot NOT most recently written. On mount, both are read and verified; higher `ss_gen` with valid csum wins.

### 7.2 Write ordering

```
stm_fs_sync:
    1. Flush main btree → writes dirty nodes (no fsync here)
    2. Flush snap tree if present
    3. Construct new superblock, compute csum
    4. Write superblock to alternate slot
    5. fsync(fd)                   ← single sync, crash boundary
    6. stm_alloc_commit             ← PENDING → free
```

A single sync is sufficient because `pwrite` orders correctly through the kernel page cache.

On Darwin, step 5 uses `fcntl(F_FULLFSYNC)` instead of `fsync()` — plain `fsync()` on macOS returns after writes reach the OS page cache but before the drive's volatile cache is flushed, so a power loss can drop a "committed" transaction and leave the next mount looking at torn state (old superblock + partially-landed new nodes). `F_FULLFSYNC` forces a real disk-cache flush. On Linux we keep `fsync()` (which on ext4/xfs does issue the disk flush).

### 7.3 File locking

`flock(LOCK_EX | LOCK_NB)` on open prevents two processes from opening the same volume path. Released automatically on process exit (kernel handles even SIGKILL). One caveat: `flock` is per-open-file-description, so two processes opening two *hardlinks* to the same inode both acquire the lock. The file backend refuses to open any file with `st_nlink > 1` as a defense.

### 7.4 Recovery

If we crash anywhere during sync:
- Superblock torn → csum mismatch → old slot wins.
- Superblock fully written → new slot wins.
- Allocator is rebuilt from scratch at next mount.

Worst case: lose the current uncommitted transaction. No corruption.

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

DEK is unwrapped on mount and used for all subsequent encrypt/decrypt. Nonce for each encryption = `cpu_to_le64(paddr)` followed by 16 zero bytes.

### 9.3 AEAD integrity

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
stratum check <path>          [--pass <p>|--pass-stdin]
stratum snap  <path> <create|list|delete|rollback> [name|id]
                               [--pass <p>|--pass-stdin]
```

### 14.1 Password handling

- `--pass <value>`: password on command line (visible in `ps`).
- `--pass-stdin`: read one line from stdin (not visible). Used by TUI to pipe password securely.

### 14.2 `check` command (fsck)

1. Read both superblocks, verify magic + csum.
2. `stm_fs_open` — fails on any bptr corruption.
3. Walk every btree node + every leaf entry + every INSERT message in internal nodes.
4. Validate: csize > 0, paddr within device, data values are 12-byte extent records with valid paddr/dlen.
5. Verify root inode exists.
6. Summary: node count, entry count, inode count, extent count + bytes, free blocks.

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

## 16. Build system

### 16.1 CMake (C)

```
cmake -B build -DCMAKE_BUILD_TYPE=Release .
cmake --build build
```

Optional dependencies (each enables a feature):
- LZ4 / ZSTD → compression
- libsodium → encryption
- xxhash → checksums

### 16.2 Cargo (Rust TUI)

```
cd tui && cargo build --release
```

---

## 17. Testing

- **11 C test suites** in `tests/`, covering types, keys, blocks, nodes, btree, fs (including 10-cycle copy-delete stress tests both plain and encrypted), compression, crypto, snapshots, 9P, allocator.
- **Rust integration tests** in `tui/tests/integration.rs`: 10 scenarios via CLI (small/large files, overwrite, sparse, binary integrity, autogrow, 200 small files, performance scaling).

---

## 18. Performance characteristics

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

## 19. Edge cases and gotchas

- **128 KiB extent + AEAD tag**: encrypted extent uses 33 blocks (128 KiB + 16 B tag rounds up).
- **Partial 9P walks**: server rejects when `newfid != fid`; client also guards.
- **Dirent collisions**: FNV1a + 256-slot linear probe. No tombstones — deletion leaves a hole that subsequent lookups respect.
- **Refcount clamp at 0xFFFE**: prevents collision with `REFCOUNT_PENDING = 0xFFFF`.
- **Deferred free under OOM**: if the deferred list can't grow, free silently reverts the refcount. Block is leaked until next mount's tree-walk rebuild.

---

## 20. Known limitations / future work

1. **No intermediate commits during long writes**. A 50 GB copy loses everything on crash before sync. (Attempted; reverted due to encryption corruption.)
2. **No node cache**. Every `stm_btree_read_node` does full malloc + I/O + decrypt + decompress + decode.
3. **No defragmentation**.
4. **Allocator state not persisted**. Rebuilt via tree walk on mount (O(total nodes + extents)).
5. **No hard links, symlinks, xattrs, rename, chown, utime**.
6. **No FUSE / kernel mount**. 9P only.
7. **No CRC on extent data independent of AEAD**. Unencrypted volumes have no integrity check on data.

---

## 21. Glossary

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
| **nonce** | XChaCha20 nonce (24 B; Stratum uses paddr LE + zeros) |
| **paddr** | Physical byte address on device |
| **PENDING** | Refcount sentinel 0xFFFF for freed-but-not-committed |
| **QID** | 9P unique-id tuple |
| **Refcount** | Per-block reference count for snapshot sharing |
| **Scratch buffer** | Reusable per-fs buffer for extent I/O |
| **Sync** | Full checkpoint (flush trees + write superblock + fsync + commit) |
| **Tag** | Poly1305 MAC (16 bytes) |
