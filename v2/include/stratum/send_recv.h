/* SPDX-License-Identifier: ISC */
/*
 * Send / receive — point-in-time dataset replication (Phase 7 P7-7).
 *
 *   see docs/ARCHITECTURE.md §8.7 — send/recv protocol intent.
 *   see docs/ROADMAP-V2.md §10.3 — Phase 7 deliverable.
 *
 * Send produces a wire-format byte stream representing the contents of
 * a dataset at a snapshot point (full send) or the delta between two
 * snapshots (incremental). Receive consumes the stream and reconstructs
 * the dataset on a target pool. The wire is plaintext — caller wraps
 * in TLS/SSH for transport. Receive re-encrypts each extent under the
 * target pool's metadata key (different key + different paddrs = a
 * fresh AEAD nonce envelope; no nonce reuse hazard across pools).
 *
 * Wire format:
 *
 *   Stream = HEADER ++ EXTENT* ++ END
 *
 *   Each record:
 *     ┌─────────┬─────────┬──────────────┐
 *     │ type    │ flags   │ body_len     │
 *     │ (le32)  │ (le32)  │ (le64)       │
 *     ├─────────┴─────────┴──────────────┤
 *     │ body (body_len bytes)            │
 *     └──────────────────────────────────┘
 *
 *   HEADER body (52 bytes):
 *     0    16   src_pool_uuid   (le64[2])
 *    16     8   dataset_id      (le64)
 *    24     8   from_snap_id    (le64; 0 = full send)
 *    32     8   to_snap_id      (le64)
 *    40     8   to_txg          (le64)
 *    48     4   reserved        (zero)
 *
 *   EXTENT body (32 + len bytes):
 *     0     8   ino             (le64)
 *     8     8   off             (le64)
 *    16     8   len             (le64)
 *    24     8   gen             (le64)  — source-side write_gen, advisory
 *    32   len   plaintext       (raw bytes)
 *
 *   END body (32 bytes):
 *     0    32   blake3_csum     — running BLAKE3 over every prior
 *                                  record's framing+body. Receiver
 *                                  refuses a stream whose computed csum
 *                                  doesn't match.
 *
 * Properties this protocol guarantees (when neither side is buggy):
 *
 *   - StreamCompleteness: a valid stream contains every extent of the
 *     source's snapshot range, exactly once.
 *   - Ordering: receive applies records in the order they were emitted;
 *     receiver refuses out-of-order streams (header must be first;
 *     END must follow only after EXTENT records of the source's range).
 *   - Authenticity: the BLAKE3 csum binds the entire stream — any
 *     tampering or truncation fails the end-of-stream check.
 *   - Nonce isolation: receiver re-encrypts; cross-pool nonce reuse
 *     impossible.
 *
 * Lifecycle:
 *
 *   sender                       receiver
 *   ──────                       ────────
 *   stm_send_init(...)           stm_recv_init(target_ds, ...)
 *   loop:                        loop:
 *     stm_send_next(buf)           stm_recv_apply(rec_bytes)
 *     send buf over wire         (may be in any number of recv_apply
 *                                 calls per record — caller frames
 *                                 records before passing in)
 *   STM_ENOENT → done            stm_recv_finish()  → STM_OK
 *   stm_send_close()             stm_recv_close()
 *
 * MVP scope:
 *   - Full sends (from_snap_id == to_snap_id == 0).
 *   - Single-dataset send (no nested ds children).
 *   - Plaintext on the wire (caller wraps for transport).
 *   - In-process tests pipe send → recv directly.
 *
 * Incremental send (P7-8): the snap-bounded form
 * (from_snap_id != 0) filters extents by
 * `snapshot.extent_txg`, the value of `sync.current_gen` captured at
 * SnapshotCreate. Since `extent.gen` is also stamped from
 * `sync.current_gen` at write time, the filter
 * `from.extent_txg < extent.gen <= to.extent_txg` is authoritative —
 * it sits in the same counter space as the values it filters.
 * The earlier `created_txg`-based filter was best-effort (different
 * counter space); P7-8 closed that gap (format break v13 → v14;
 * `snapshot.tla::ExtentTxgBoundedBySync`).
 *
 * Operational requirement: for the filter to be EXACT (no extents at
 * gen == snap.extent_txg falling on the wrong side of the boundary),
 * the caller MUST `stm_sync_commit` immediately after every
 * `stm_snapshot_create` so that subsequent extent writes happen at
 * `sync.current_gen` strictly greater than the snap's captured
 * `extent_txg`. Without this, multiple writes can share a sync_gen
 * with a snap-create — the filter then conservatively classifies
 * such ambiguous extents as pre-snap. ZFS's TXG model handles this
 * via implicit commit-on-snap; we track it as a documented protocol
 * obligation rather than an internal commit (avoids surprise I/O
 * inside `stm_snapshot_create`). Tests in `test_send_recv.c` exhibit
 * the bracketed pattern: `commit → snap_create → commit`.
 *
 * MVP caveat — stale-paddr during long sends (R39 P3-1): send_init
 * snapshots `paddrs[0..n_replicas-1]` at the time of the call. If
 * the source pool runs `stm_sync_commit` while the send is in
 * flight AND the source overwrites the snapshotted extent AND the
 * commit reaps the prior paddrs from PENDING to FREE AND a fresh
 * write reuses the paddr at a new gen, the next `stm_send_next`
 * for that extent reads bytes encrypted under a different
 * (paddr, gen) pair — AEAD verify fails with STM_EBADTAG. The
 * failure is clean (no silent corruption) but interrupts the
 * send. To avoid this on busy source pools, callers should either
 * (a) pause writes during send, or (b) snapshot the source first
 * (the snapshot's tree_root captures a stable view; future
 * snap-bounded incremental sends will source from the snapshot).
 *
 * MVP caveat — recv durability (R39 P3-2): a successful
 * `stm_recv_finish` returns STM_OK once HEADER + every EXTENT +
 * END have been applied AND the END's csum verifies. The applied
 * extents are written to disk via `stm_sync_write_extent` (which
 * encrypts + bdev_writes) but are NOT durable until the next
 * `stm_sync_commit`. A host crash between `stm_recv_finish` and
 * the next sync-level commit loses every received extent; on
 * remount the extent index restores from the previously-committed
 * root. Callers MUST call `stm_sync_commit` (or the higher-level
 * fs-commit equivalent) before declaring the recv durable.
 * Future work: have `stm_recv_finish` issue an internal commit
 * before returning OK, gated by a flag.
 *
 * Out of scope (future chunks):
 *   - Nested dataset (recursive send).
 *   - Resumable receive (mid-stream checkpoint).
 *   - Compression on the wire.
 *   - Encrypted-at-rest send (ship ciphertext + key envelope; needs
 *     PQ-hybrid wrap of the source's metadata key for the receiver
 *     — separate spec + chunk).
 */
#ifndef STRATUM_V2_SEND_RECV_H
#define STRATUM_V2_SEND_RECV_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_sync; typedef struct stm_sync stm_sync;

/* Wire constants. */
#define STM_SEND_MAGIC          UINT32_C(0x534D5453)   /* "STMS" little-endian */
#define STM_SEND_VERSION        1u

/* Record types (stored in the type field of every record's framing
 * header). */
typedef enum {
    STM_SEND_REC_HEADER  = 1,
    STM_SEND_REC_EXTENT  = 2,
    STM_SEND_REC_END     = 3,
} stm_send_record_type;

/* Per-record framing length (preceding every body). */
#define STM_SEND_RECORD_HDR_LEN  16u
/* HEADER body length. */
#define STM_SEND_HEADER_BODY_LEN 52u
/* EXTENT body's metadata length (followed by `len` plaintext bytes). */
#define STM_SEND_EXTENT_META_LEN 32u
/* END body length (BLAKE3 csum). */
#define STM_SEND_END_BODY_LEN    32u

/* Upper bound on a single record's full bytes (framing + body) — used
 * by recv to reject hostile/oversized records up front before any
 * dispatch. The largest legitimate record is an EXTENT carrying a
 * full 128 KiB plaintext payload: 16 (framing) + 32 (meta) + 131072
 * (plaintext) = 131120 bytes. R39 P2-3. */
#define STM_SEND_RECORD_MAX_LEN  (STM_SEND_RECORD_HDR_LEN +              \
                                    STM_SEND_EXTENT_META_LEN +           \
                                    (128u * 1024u))

/* ========================================================================= */
/* Send.                                                                      */
/* ========================================================================= */

struct stm_send_handle;
typedef struct stm_send_handle stm_send_handle;

/*
 * Open a send handle over `sync`. Caller selects:
 *   - dataset_id: the source dataset to send.
 *   - from_snap_id: 0 means "full send" (every extent in the dataset's
 *                    current state). Non-zero means "incremental from
 *                    that snapshot": only extents with gen >
 *                    from_snap.created_txg are included.
 *   - to_snap_id: 0 means "current state" (no upper bound). Non-zero
 *                  means "up to this snapshot": only extents with
 *                  gen ≤ to_snap.created_txg are included.
 *
 * Returns:
 *   STM_OK on success; *out_handle is the opaque handle.
 *   STM_EINVAL on NULL args, dataset_id == 0, or invalid snap pair.
 *   STM_ENOENT if the dataset doesn't exist or a referenced snap
 *     doesn't exist as PRESENT.
 *   STM_ENOMEM on allocation failure.
 *
 * Lifetime: `sync` must outlive the handle. Send does not mutate
 * sync's state; it reads via the extent / snapshot indices.
 */
STM_MUST_USE
stm_status stm_send_init(stm_sync *sync,
                            uint64_t dataset_id,
                            uint64_t from_snap_id,
                            uint64_t to_snap_id,
                            stm_send_handle **out_handle);

/*
 * Emit the next record's wire bytes into `out_buf`.
 *
 * Output: the framed bytes (header[16] + body[N]) for the next record
 * in the stream. *out_len is set to the total byte count written.
 *
 * If `out_cap` < the next record's total length, no bytes are written
 * and STM_ERANGE is returned with *out_len_needed set to the required
 * size; caller retries with a sufficient buffer.
 *
 * Stream order:
 *   1st call: HEADER record.
 *   subsequent calls: EXTENT records, one per extent in the snapshot
 *     range (in (ino, off) ascending order across the whole dataset).
 *   final call: END record (carries the running BLAKE3 csum).
 *   after END is emitted, returns STM_ENOENT.
 *
 * Returns:
 *   STM_OK    — record emitted; consume *out_len bytes.
 *   STM_ENOENT — stream complete.
 *   STM_ERANGE — out_cap too small; *out_len_needed advises.
 *   STM_EBADTAG / STM_EIO / STM_EPROTOCOL on internal verify failures
 *     (couldn't decrypt a source extent — corruption mid-send).
 */
STM_MUST_USE
stm_status stm_send_next(stm_send_handle *h,
                            void *out_buf, size_t out_cap,
                            size_t *out_len,
                            size_t *out_len_needed);

void stm_send_close(stm_send_handle *h);

/* ========================================================================= */
/* Receive.                                                                   */
/* ========================================================================= */

struct stm_recv_handle;
typedef struct stm_recv_handle stm_recv_handle;

/*
 * Open a recv handle. `target_dataset_id` is the dataset on `sync`'s
 * pool to write into. Caller is responsible for ensuring the dataset
 * exists and for any pre-existing-conflict semantics.
 *
 * Returns STM_OK on success, STM_EINVAL on NULL args / zero ds.
 */
STM_MUST_USE
stm_status stm_recv_init(stm_sync *sync,
                            uint64_t target_dataset_id,
                            stm_recv_handle **out_handle);

/*
 * Apply one framed record's bytes. Caller MUST pass exactly one
 * record's complete bytes (framing header + body); fragmentation is
 * the caller's reassembly responsibility.
 *
 * State machine:
 *   First call MUST be a HEADER record (validates magic / version /
 *     pool_uuid expectations; after success, recv expects EXTENTs).
 *   Subsequent EXTENT records are dispatched to stm_sync_write_extent
 *     under target_dataset_id.
 *   Final END record triggers csum verification; recv enters terminal
 *     state.
 *
 * Returns:
 *   STM_OK    — record accepted.
 *   STM_EINVAL — NULL / zero-len record.
 *   STM_ECORRUPT — malformed framing, body_len mismatch, unknown type,
 *                  out-of-order (HEADER not first, EXTENT after END,
 *                  etc.).
 *   STM_EBADVERSION — header magic or version doesn't match.
 *   STM_EBADTAG — END's csum doesn't match recv's running BLAKE3.
 *   plus any error from the underlying stm_sync_write_extent.
 */
STM_MUST_USE
stm_status stm_recv_apply(stm_recv_handle *h,
                             const void *record_bytes,
                             size_t record_len);

/*
 * Finalize the recv. Returns STM_OK iff:
 *   - HEADER was received first.
 *   - END was received last.
 *   - END's csum verified.
 * Otherwise STM_EPROTOCOL (stream incomplete / no END).
 */
STM_MUST_USE
stm_status stm_recv_finish(stm_recv_handle *h);

void stm_recv_close(stm_recv_handle *h);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SEND_RECV_H */
