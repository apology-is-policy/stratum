/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — dirty buffer (SWISS-4q-flush).
 *
 * Per-inode plaintext write buffer that sits between stm_fs_write and
 * stm_sync_write_extent. Realizes the BufferedWrite + Flush actions
 * modeled in `v2/specs/writeback.tla`. The buffer absorbs many small
 * writes per inode and emits them at flush time as fewer/larger extents
 * (coalesced contiguous ranges), cutting allocator + AEAD overhead for
 * many-small-writes workloads (tarball unpack, code build, browser
 * cache, container layers).
 *
 * Spec-to-code:
 *   - stm_dirty_buffer_insert   → writeback.tla::BufferedWrite
 *   - stm_dirty_buffer_lookup   → writeback.tla::ReadSeq (buffer overlay)
 *   - stm_dirty_buffer_drain_*  → writeback.tla::Flush
 *   - stm_dirty_buffer_drop_ino → no spec action (used by unlink/truncate;
 *                                  unbuffered data simply disappears with
 *                                  the inode; the spec's DeleteFile action
 *                                  implicitly handles this at the extent
 *                                  layer).
 *
 * Concurrency: every public call takes the buffer's own mutex. Callers
 * MAY hold fs->lock; the lock ordering is fs->lock outer → dbuf->lock
 * inner. Inverting would risk deadlock with future code paths that touch
 * both. For v1 the FS is single-threaded under fs->lock anyway, so the
 * dbuf->lock is uncontested — kept defensively for the day per-inode FS
 * locks land.
 *
 * Memory: every range owns its plaintext buffer (heap-allocated, copied
 * from the caller's data on insert). The buffer's internal arena is
 * malloc-based; future migration to a slab allocator is a v2 perf knob.
 *
 * Cap policy: per-inode cap + global cap, both in bytes. An insert that
 * would push EITHER cap past the limit fails with STM_ENOSPC; the caller
 * (fs.c) MUST drain (= flush) before retrying. The retry-on-ENOSPC dance
 * is documented in stm_fs_write_regular_locked's comments.
 */
#ifndef STRATUM_V2_DIRTY_BUFFER_H
#define STRATUM_V2_DIRTY_BUFFER_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stm_dirty_buffer stm_dirty_buffer;

/*
 * Create a fresh dirty buffer with the given per-inode + global caps
 * (both in bytes). Recommended defaults for v1: per_inode_cap_bytes =
 * 8 MiB (= STM_FS_RECORDSIZE_MAX), global_cap_bytes = 256 MiB.
 *
 * Returns STM_EINVAL on NULL out / zero caps, STM_ENOMEM on alloc fail.
 */
STM_MUST_USE
stm_status stm_dirty_buffer_create(size_t per_inode_cap_bytes,
                                       size_t global_cap_bytes,
                                       stm_dirty_buffer **out);

/*
 * Destroy the buffer + free all owned plaintext. SAFE to call with
 * non-empty buffer — any buffered data is silently dropped (NOT
 * flushed). Callers that want to flush MUST call stm_dirty_buffer_
 * drain_all FIRST.
 */
void stm_dirty_buffer_destroy(stm_dirty_buffer *buf);

/*
 * Insert a write at (dataset_id, ino, off, off+len). The caller's
 * `data` is COPIED into the buffer (the buffer owns the storage).
 *
 * Per writeback.tla::BufferedWrite: any existing buffered range for
 * (dataset_id, ino) that OVERLAPS [off, off+len) is REPLACED. The
 * unique-bytes effect is last-writer-wins.
 *
 * v1 semantics — entire-range replacement on overlap:
 *   The v1 impl DROPS any overlapping existing range in its entirety,
 *   even if the new write only partially overlaps it. Example: existing
 *   [0, 100), new write [50, 120) → existing is dropped; only the new
 *   range remains. Bytes [0, 50) that the writer expected to persist
 *   are LOST from the buffer.
 *
 *   This is correct under the writer's mental model PROVIDED the FS
 *   layer above always re-reads through to the extent layer for any
 *   buffer-miss range (which it does — the lookup-then-fallthrough
 *   path in stm_fs_read covers this). In practice, the existing
 *   range's bytes are either (a) already on disk from a prior flush
 *   that the new write partially-shadows, or (b) part of a pending
 *   write that gets fully overwritten by the new one. Case (a) means
 *   bytes [0, 50) are recoverable via the extent layer. Case (b) is
 *   the writer rewriting their own pending data — they don't care
 *   about the discarded prefix.
 *
 *   v2 forward-note: a smarter impl would SPLIT the existing range
 *   into non-overlapping prefix [0, 50) + suffix (none in this case)
 *   and keep them in the buffer. This avoids the buffer-miss cost
 *   for partial overlap. Until that lands, callers can assume the
 *   simpler "any overlap drops the old range" semantics and the
 *   extent-layer fallback covers correctness.
 *
 * Returns:
 *   STM_OK       — success.
 *   STM_EINVAL   — NULL args, zero len.
 *   STM_ENOMEM   — allocation failure.
 *   STM_ENOSPC   — insertion would exceed per-inode or global cap.
 *                  Caller MUST drain (this inode, or all) and retry.
 *                  Per writeback.tla::BufferBoundedSize invariant.
 *
 * Concurrency: takes buf->mu internally.
 */
STM_MUST_USE
stm_status stm_dirty_buffer_insert(stm_dirty_buffer *buf,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       const void *data);

/*
 * Read-overlay lookup: copies into `out_buf` the LONGEST contiguous
 * prefix of [off, off+len) that is covered by buffered ranges for
 * (dataset_id, ino), and sets *out_covered to the byte count copied.
 *
 *   *out_covered == len   → the entire requested range is in the buffer.
 *   *out_covered <  len   → the first *out_covered bytes are in the
 *                            buffer; the remaining bytes are NOT
 *                            (caller must fall through to the extent
 *                            layer for those).
 *   *out_covered == 0    → the (off) byte itself isn't in the buffer.
 *
 * Returns STM_OK on success (including the zero-covered case).
 * Returns STM_EINVAL on NULL args.
 *
 * Concurrency: takes buf->mu internally.
 */
STM_MUST_USE
stm_status stm_dirty_buffer_lookup(stm_dirty_buffer *buf,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       void    *out_buf,
                                       size_t  *out_covered);

/*
 * Per-range callback passed to drain_ino / drain_all. The callback's
 * responsibility is to encrypt + write the range to the extent layer
 * (stm_sync_write_extent or similar). The buffer-owned `data` is valid
 * only for the duration of the callback; after the callback returns
 * the buffer may free or reuse it.
 *
 * Returns STM_OK if the range was successfully realized in the extent
 * layer; non-OK on failure. On non-OK return, the buffer treats the
 * drain as failed and LEAVES the range intact (per writeback.tla
 * "Flush is all-or-nothing per call" — partial drain is a buggy
 * variant and not allowed).
 */
typedef stm_status (*stm_dirty_buffer_drain_cb)(
    void           *user,
    uint64_t        dataset_id,
    uint64_t        ino,
    uint64_t        off,
    uint64_t        len,
    const void     *data);

/*
 * Drain all buffered ranges for one inode via `cb`. Ranges are emitted
 * in ASCENDING off order so the callback sees a sorted stream.
 *
 * Per writeback.tla::Flush, this is all-or-nothing: if ANY callback
 * call returns non-OK, the partially-drained ranges are RESTORED to
 * the buffer (the callback's prior successful writes are NOT reverted
 * — they remain in the extent layer; the inode just keeps its buffer
 * coherent for further writes). Returns the first non-OK status if
 * one occurred, else STM_OK.
 *
 * Note on partial-success semantics: the C impl's all-or-nothing
 * guarantee covers BUFFER coherence — it does NOT undo extent-layer
 * side effects. If the callback writes 2 extents successfully and the
 * 3rd fails, the 2 extents remain written; the buffer keeps all 3
 * ranges (so re-flush emits the 2 again, producing duplicates that
 * extent.tla::Overwrite will resolve). The user-visible read returns
 * the same bytes either way (latest-writer-wins via src_seq), so the
 * spec's ReadHidesFlushOrder holds.
 *
 * Concurrency: takes buf->mu for the duration of the drain. Callback
 * runs UNDER buf->mu; the callback MUST NOT call back into the buffer
 * (would deadlock).
 */
STM_MUST_USE
stm_status stm_dirty_buffer_drain_ino(stm_dirty_buffer *buf,
                                          uint64_t dataset_id, uint64_t ino,
                                          stm_dirty_buffer_drain_cb cb,
                                          void *user);

/*
 * Drain every inode. Per-inode semantics as drain_ino. Returns the
 * first non-OK status if any inode's drain failed, else STM_OK.
 *
 * Iteration order is implementation-defined (not by dataset_id/ino).
 *
 * Concurrency: takes buf->mu for the duration.
 */
STM_MUST_USE
stm_status stm_dirty_buffer_drain_all(stm_dirty_buffer *buf,
                                          stm_dirty_buffer_drain_cb cb,
                                          void *user);

/*
 * Drop every buffered range for (dataset_id, ino) WITHOUT flushing.
 * Used by stm_fs_unlink / stm_fs_truncate-to-zero — the inode is going
 * away (or its extents are being dropped), so the buffered plaintext
 * is no longer reachable. Safe to call when the inode has no buffered
 * data (no-op).
 *
 * Concurrency: takes buf->mu internally.
 */
void stm_dirty_buffer_drop_ino(stm_dirty_buffer *buf,
                                   uint64_t dataset_id, uint64_t ino);

/*
 * Return the per-inode buffered byte count. Used by callers to decide
 * whether to pre-flush (e.g., to keep latency low at fsync time).
 *
 * Concurrency: takes buf->mu internally.
 */
size_t stm_dirty_buffer_inode_bytes(stm_dirty_buffer *buf,
                                        uint64_t dataset_id, uint64_t ino);

/*
 * Return the total buffered byte count across all inodes.
 *
 * Concurrency: takes buf->mu internally.
 */
size_t stm_dirty_buffer_total_bytes(stm_dirty_buffer *buf);

/*
 * Return true if the buffer holds any range for (dataset_id, ino).
 * Used by fs_unlink to decide whether to call drop_ino (cheap probe).
 *
 * Concurrency: takes buf->mu internally.
 */
bool stm_dirty_buffer_has_ino(stm_dirty_buffer *buf,
                                  uint64_t dataset_id, uint64_t ino);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_DIRTY_BUFFER_H */
