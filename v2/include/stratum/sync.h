/* SPDX-License-Identifier: ISC */
/*
 * Commit protocol — single-device (sync.tla) + multi-device quorum
 * (quorum.tla).
 *
 *   see v2/specs/sync.tla         — single-device four-phase spec.
 *   see v2/specs/quorum.tla       — multi-device quorum spec (P5-0).
 *   see ARCHITECTURE §3.7, §5.6   — commit + uberblock ring.
 *   see ARCHITECTURE §7.4         — nonce uniqueness + MountGenBump.
 *
 * `stm_sync` owns the uberblock ring across a pool's devices and
 * orchestrates the commit protocol. It sits above `stm_alloc`
 * (allocator state + data-area tree persistence) and below future
 * per-FS machinery.
 *
 * Commit protocol (P5-2 multi-device, two-phase):
 *
 *   Reservation — write UB at gen=auth+1 to every pool device,
 *                  fsync each, wait for quorum (⌊N/2⌋+1) of
 *                  confirmations. Reservation UB content = copy of
 *                  the previous authoritative UB with ub_gen bumped
 *                  (pre-flush roots; rollback target if Phase 3
 *                  fails). If quorum is not reached, commit aborts;
 *                  no flush occurs.
 *   Flush        — persist dirty data + new tree nodes. Driven by
 *                  stm_keyschema_commit + stm_alloc_commit (each at
 *                  gen=target_gen=auth+2). Per-block writes do not
 *                  require quorum — their durability is anchored by
 *                  the final UB referencing them.
 *   Final        — write UB at gen=target to every pool device,
 *                  fsync each, wait for quorum. Final UB content =
 *                  post-flush roots + post-flush Merkle root. This
 *                  is the commit point.
 *   Publish      — in-RAM auth_gen := target. current_gen := auth+2.
 *
 *   Each commit therefore advances the authoritative gen by 2.
 *   Mount-claim advances it by 1.
 *
 *   The first commit on a fresh pool (auth==0) is 1-phase: only the
 *   final UB is written at gen=1. There's no "pre-flush" state to
 *   preserve. Subsequent commits are full 2-phase.
 *
 * Mount logic (P5-2): for each pool device, scan every label × 63
 * commit-ring slot; collect valid uberblocks. The authoritative gen
 * is the highest gen G with |{device : ub_device.gen >= G}| >=
 * ⌊N/2⌋+1. If no quorum exists, mount fails. Otherwise the mount
 * writes a claim UB at auth+1 on every online device and requires
 * quorum. This protects nonce uniqueness across crash recovery (R9
 * P0-1) and the MountGenBumpMulti invariant in quorum.tla.
 *
 * Ring rotation (per device, deterministic):
 *   label = gen % STM_LABELS_PER_DEVICE
 *   slot  = gen % STM_UB_SLOTS_PER_LABEL
 */
#ifndef STRATUM_V2_SYNC_H
#define STRATUM_V2_SYNC_H

#include <stratum/types.h>
#include <stratum/pool.h>      /* stm_pool_device — used in replace_device_online */

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;         typedef struct stm_bdev  stm_bdev;
struct stm_alloc;        typedef struct stm_alloc stm_alloc;
struct stm_hybrid_keys;  typedef struct stm_hybrid_keys stm_hybrid_keys;
struct stm_janus_client;

/* ========================================================================= */
/* Redundancy profile (P5-3a).                                                */
/* ========================================================================= */

/*
 * Pool-wide redundancy profile (ARCH §4.5). Declared at pool format,
 * persisted in every uberblock's ub_redundancy_kind + ub_redundancy_params,
 * and consumed by the allocator + write path.
 *
 * P5-3a: plumbing only — the profile is carried through sync and stamped
 * into every UB. Actual use (mirror reservation + fan-out) lands in P5-3c.
 *
 * Param encoding, per kind:
 *   STM_RED_NONE:   all 15 params bytes zero.
 *   STM_RED_MIRROR: params[0] = n (replica count, 1..64).
 *                   params[1..15] zero.
 *   STM_RED_RS / STM_RED_LRC: reserved (refused with STM_ENOTSUPPORTED
 *                              at create; mount decodes but treats as
 *                              forward-incompatible).
 *
 * Validation (sync_create + sync_open):
 *   - kind in {NONE, MIRROR}; RS / LRC → STM_ENOTSUPPORTED.
 *   - if MIRROR: n in [1 .. stm_pool_device_count(pool)]. n=1 is allowed
 *     (degenerate "mirror of one" — equivalent to NONE but intentional,
 *     useful for testing the mirror write path on single-device pools).
 *   - tail params bytes must be zero (rejects encoding drift + tamper).
 */
typedef struct {
    uint8_t kind;              /* stm_redundancy_kind */
    uint8_t mirror_n;          /* valid when kind == STM_RED_MIRROR */
} stm_redundancy_profile;

/* ========================================================================= */
/* Opaque handle + info.                                                      */
/* ========================================================================= */

typedef struct stm_sync stm_sync;

typedef struct {
    /* Authoritative gen — the gen of the most recent committed final
     * UB with quorum. Includes mount-claim UBs (which advance auth
     * by 1 without flushing data). 0 on a fresh handle before the
     * first commit. */
    uint64_t auth_gen;

    /* Next commit's final gen:
     *   - fresh (auth=0):  1 (first commit is 1-phase at gen=1).
     *   - otherwise:       auth + 2 (2-phase; reservation at auth+1,
     *                                final at auth+2).
     * Kept as `current_gen` for API continuity; reflects "gen the
     * NEXT commit will end up at" (matches pre-P5-2 semantic). */
    uint64_t current_gen;

    /* Highest gen with quorum on-disk at the last open/mount. */
    uint64_t mount_max_durable_gen;

    /* Most-recent final UB's ring location. Same (label, slot) across
     * every pool device (rotation is gen-indexed, and per-device rings
     * are synchronized at every commit). */
    uint32_t live_label_idx;
    uint32_t live_slot_idx;

    /* Allocator-tree root paddr recorded in the last committed uberblock.
     * 0 if no commits yet. */
    uint64_t alloc_root_paddr;
} stm_sync_info;

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Create a fresh pool's sync state. Borrows `a` and `p` (not owned);
 * `a` must already be open via stm_alloc_create. Writes NO initial
 * uberblock — callers should call stm_sync_commit to land the first
 * durable checkpoint.
 *
 * `p` (P5-1): supplies pool identity (pool_uuid, per-device uuid,
 * role, class, state, size) and the block devices written during
 * commit. The uberblock's ub_pool_uuid / ub_device_uuid / roster /
 * class / role fields are populated from `p`. `p` must have at least
 * one device; P5-1 writes to device 0 (degenerate N=1). Multi-device
 * quorum commit lands in P5-2.
 *
 * `wk` (P4-4a): the hybrid wrap key-pair. `wk->pk` is used at
 * format time to PQ-hybrid-wrap the pool's dataset key. `wk->sk`
 * must also be populated so the handle can operate without needing
 * a separate unwrap call (a fresh pool uses the dataset key
 * immediately for metadata encryption).
 *
 * `profile` (P5-3a): pool-wide redundancy profile. NULL == treat as
 * {kind = STM_RED_NONE}. Validated per `stm_redundancy_profile`
 * contract above; invalid inputs return STM_EINVAL /
 * STM_ENOTSUPPORTED before any on-disk state is created.
 */
STM_MUST_USE
stm_status stm_sync_create(stm_pool *p, stm_alloc *a,
                            const stm_hybrid_keys *wk,
                            const stm_redundancy_profile *profile,
                            stm_sync **out_sync);

/*
 * Mount-time open. Scans all labels × commit ring slots, picks the
 * authoritative uberblock (highest valid gen), and:
 *   - bumps current_gen to (authoritative_gen + 1) per the
 *     MountGenBump invariant (sync.tla).
 *   - if the uberblock carries a valid `ub_alloc_root`, calls
 *     stm_alloc_load_tree_at(a, paddr) to rehydrate the tree.
 *
 * `a` must be opened via stm_alloc_open_blank (the allocator handle
 * starts with an empty tree; this function loads it from the
 * uberblock's ub_alloc_root).
 *
 * Returns STM_ENOENT when no valid uberblock exists on the device
 * (operator needs stm_sync_create, not _open). Returns STM_ECORRUPT
 * if the selected uberblock's ub_alloc_root has a nonzero paddr but
 * the wrong kind (tampering indicator). Returns STM_ERANGE if the
 * durable gen is UINT64_MAX or UINT64_MAX-1 (cannot MountGenBump).
 *
 * On ANY failure, `*a` may be in a partially-loaded state (if the
 * failure was in stm_alloc_load_tree_at); callers should discard
 * the handle via stm_alloc_close and not reuse it.
 */
/*
 * P4-4b: `wk` and `janus` are mutually exclusive — exactly one must
 * be non-NULL. `wk` uses the in-process unwrap path (keyfile / legacy);
 * `janus` routes the unwrap over the 9P socket to a remote daemon.
 */
STM_MUST_USE
stm_status stm_sync_open(stm_pool *p, stm_alloc *a,
                          const stm_hybrid_keys *wk,
                          struct stm_janus_client *janus,
                          stm_sync **out_sync);

/*
 * Commit. Writes Phase 1 reservation UB at auth+1, flushes, writes
 * Phase 3 final UB at auth+2, to every pool device in parallel.
 * Each phase requires quorum (⌊N/2⌋+1) of fsync confirmations; if
 * either phase lacks quorum, the commit aborts with STM_EQUORUM
 * and the in-RAM state is unchanged.
 *
 * On STM_OK, auth_gen has advanced by 2 (one commit) and the pool's
 * devices hold quorum-confirmed UBs at the reservation and final
 * gens.
 *
 * The first commit on a fresh pool (auth_gen==0) is 1-phase: only
 * the final UB is written at gen=1. There is no pre-flush state to
 * preserve on rollback.
 *
 * Known MVP caveat (R7d P0-2): a crash between the internal
 * stm_alloc_commit (which flushes bootstrap state) and the Phase 3
 * UB writes leaks bootstrap-pool bitmap bits for the tree nodes
 * written for the in-flight commit. The next mount picks the Phase
 * 1 reservation (CommitAtomic holds — orphan tree nodes are
 * unreachable), but the bitmap bits remain allocated until a future
 * fsck pass reconciles. Leak-on-failure, not corruption.
 */
STM_MUST_USE
stm_status stm_sync_commit(stm_sync *s);

/*
 * Release the handle. Does NOT commit; callers who need durability
 * must call stm_sync_commit first. Does NOT close the underlying
 * stm_alloc — the caller owns that lifecycle.
 *
 * Callers must ensure no other thread is using `s` at close time.
 * close does not self-quiesce and destroys the internal mutex
 * (destroying a locked mutex is undefined behavior per POSIX).
 *
 * Lifetime contract (R13 P2-1): the stm_pool * passed to
 * stm_sync_create / stm_sync_open is borrowed and dereferenced on
 * every commit. It MUST remain valid until stm_sync_close returns;
 * do not call stm_pool_close on the pool until the sync handle has
 * been closed.
 */
void stm_sync_close(stm_sync *s);

/* ========================================================================= */
/* P5-durable-cursors — scrub state durable bytes (push from scrub).          */
/* ========================================================================= */

/* Update the 64-byte durable scrub-state region that sync persists
 * on the next stm_sync_commit. The bytes must match the layout
 * documented for `stm_uberblock.ub_scrub_state[64]` (see
 * stm_ub_scrub_state_pack in <stratum/super.h>).
 *
 * Push-from-scrub design (vs a sync→scrub callback): scrub.c calls
 * this after every state-changing op (Start, Pause, Resume, Reset,
 * Restart, Step, ...). The setter takes sync's internal lock
 * briefly to memcpy the bytes; sync_commit reads from its buffer
 * with no further coordination. Avoids the lock inversion that a
 * sync→scrub callback would create (sync_commit holds sync.lock
 * and would need scrub's lock; scrub_step holds sc.lock and uses
 * stm_sync_alloc which briefly takes sync.lock).
 *
 * Caller must already hold its own scrub-side lock (if any) when
 * computing the bytes; this function does not coordinate with the
 * scrub side.
 *
 * Lock order: sc.lock (caller-held) OUTER → sync.lock INNER (taken
 * briefly by this setter). Symmetric with stm_scrub_step's existing
 * use of stm_sync_alloc.
 *
 * Returns STM_EINVAL on NULL args.
 */
STM_MUST_USE
stm_status stm_sync_set_scrub_durable_bytes(stm_sync     *s,
                                              const uint8_t bytes[64]);

/* Read back the durable scrub-state bytes that sync currently holds.
 * After sync_open, this returns the bytes that were on disk in the
 * authoritative UB at mount time — useful for stm_scrub_create to
 * restore the in-RAM state at handle init.
 *
 * Always succeeds for a valid handle; never blocks (reads under the
 * sync lock briefly). Buffer is exactly 64 bytes.
 */
void stm_sync_get_scrub_durable_bytes(const stm_sync *s,
                                        uint8_t out[64]);

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_sync_info_get(const stm_sync *s, stm_sync_info *out);

/*
 * Return the pool's redundancy profile (set at create from the
 * caller-supplied profile, at open from the mounted UB). Always
 * returns STM_OK — the profile is always well-formed past
 * sync_create / sync_open success (their validation rejects
 * malformed profiles up-front).
 */
STM_MUST_USE
stm_status stm_sync_redundancy_get(const stm_sync *s,
                                     stm_redundancy_profile *out);

/*
 * P5-5-α: scrub support. Return borrowed pointers to sync-owned state
 * that the scrub subsystem reads. Both are const-correct snapshot reads:
 * the pool and allocs are borrowed, not owned.
 *
 * `stm_sync_pool`  — the pool handle (always non-NULL post-create/open).
 * `stm_sync_alloc` — the alloc attached at `device_id`, or NULL if none
 *                     is attached (REMOVED slot, or never attached).
 *                     Safe against concurrent sync_commit (allocs[] is
 *                     stable between attach/detach events; the caller
 *                     is responsible for handling transient NULLs in a
 *                     concurrent remove scenario).
 *
 * Lifetime: the returned pointers are valid until the NEXT operation
 * that could change sync's attach table (attach_alloc, finish_evacuation,
 * replace_device_online) completes. For scrub — which drives steps
 * serially and holds no long-lived pointer — this is sufficient.
 */
stm_pool  *stm_sync_pool(const stm_sync *s);
stm_alloc *stm_sync_alloc(const stm_sync *s, uint16_t device_id);

/*
 * P7-7: pool-wide metadata key accessor (read-only). Returns the
 * 32-byte AEAD key sync uses for extent encrypt/decrypt. Intended
 * for the send/recv module — send decrypts source extents under this
 * key; recv re-encrypts under its own pool's key. Caller MUST NOT
 * persist or transmit the returned bytes; the key is sensitive
 * material kept in RAM. Returns NULL on NULL arg.
 *
 * Lifetime: pointer is valid for the lifetime of `s` (key is set at
 * sync_create + restored at sync_open; never mutated thereafter).
 */
const uint8_t *stm_sync_metadata_key(const stm_sync *s);

/*
 * P7-8: read-only snapshot of sync's current_gen. Returned value
 * is the gen at which the next extent-write will land — the same
 * value `stm_sync_write_extent` stamps into `extent.gen`. Callers
 * use this to capture an extent-txg-bound for a fresh snapshot via
 * `stm_snapshot_create`'s `extent_txg` argument; the captured value
 * then bounds `extent.gen` for snap-bounded send filtering.
 *
 * Returns 0 on NULL arg. Otherwise the caller's snapshot of
 * s->current_gen taken under sync's lock — value is valid as of
 * the call's instant; concurrent commits may advance it before the
 * caller observes the return.
 */
uint64_t stm_sync_current_gen(const stm_sync *s);

/* ========================================================================= */
/* P5-3c: multi-device alloc attach + mirror APIs.                             */
/* ========================================================================= */

/*
 * Attach `alloc` to sync as the allocator for `device_id`. The
 * primary alloc (device 0) is set at stm_sync_create / _open time;
 * use this to register additional per-device allocators for mirror
 * (n>1) reservations.
 *
 * Prerequisites:
 *   - device_id in (0, stm_pool_device_count(pool)); device_id == 0
 *     is already attached and cannot be replaced.
 *   - `alloc` MUST have its device_id set via stm_alloc_set_device_id
 *     to match the argument here.
 *   - The attached alloc is BORROWED; caller owns its lifecycle and
 *     must keep it alive until stm_sync_close returns.
 *   - The attached alloc MUST NOT already be registered for another
 *     device_id.
 *   - MUST be called before the first stm_sync_commit that writes
 *     durable state referencing device_id's alloc tree.
 *
 * Returns STM_EEXIST if a slot is already filled for device_id.
 * Returns STM_EINVAL on range / shape violations.
 */
STM_MUST_USE
stm_status stm_sync_attach_alloc(stm_sync *s, uint16_t device_id,
                                   stm_alloc *alloc);

/*
 * Mirror reservation. Reserves `nblocks` blocks on each of the first
 * `n_replicas` devices in the pool, returning their paddrs in
 * `out_paddrs[0..n_replicas-1]`. Each paddr's top 16 bits encode its
 * device_id.
 *
 * `n_replicas` MUST equal the pool's declared `mirror_n` (set at
 * create via profile). STM_EINVAL on mismatch.
 *
 * Each target device MUST have an attached alloc (via
 * stm_sync_attach_alloc or as the primary). STM_EINVAL on any missing
 * alloc.
 *
 * Atomicity: partial-failure cleanup. If any per-device reserve
 * fails, every already-reserved paddr is freed before returning the
 * error. On success, all n_replicas reservations are live and
 * consistent.
 */
STM_MUST_USE
stm_status stm_sync_reserve_mirror(stm_sync *s, uint64_t nblocks,
                                      size_t n_replicas,
                                      uint64_t out_paddrs[]);

/*
 * Write `buf[0..len)` to every paddr in `paddrs[0..n)`, fsyncing
 * each device after its write. Returns STM_OK if at least
 * ⌊n/2⌋+1 devices confirmed (write + fsync both STM_OK). `out_n_
 * confirmed` (may be NULL) receives the actual confirmation count.
 *
 * `len` MUST be a multiple of STM_UB_SIZE (4096). Each paddr's top
 * 16 bits select the target device; the low 48 bits are the starting
 * block offset. No length / range validation of the paddrs happens
 * here — caller typically got them from stm_sync_reserve_mirror.
 *
 * Returns STM_EQUORUM on sub-quorum confirmation (pool left with
 * some replicas durable, others not; scrub / retry reconciles).
 */
STM_MUST_USE
stm_status stm_sync_mirror_write(stm_sync *s, const uint64_t paddrs[],
                                    size_t n, const void *buf, size_t len,
                                    size_t *out_n_confirmed);

/*
 * Read from any of the `n` replicas into `buf`. Tries paddrs in
 * order; on each read, verifies BLAKE3-256(buf) against
 * `expected_csum`. First match wins. Returns STM_OK on success (buf
 * holds the verified replica). STM_ECORRUPT if NO replica produces
 * a csum match.
 *
 * `expected_csum` is typically the parent bptr's bp_csum, i.e., the
 * plaintext csum of what was written via stm_sync_mirror_write.
 * AEAD-layered callers (future extent manager) use AEAD decryption
 * as the integrity gate; for this layer we expose the plaintext
 * csum primitive.
 *
 * On read I/O failure for an individual replica (not ECORRUPT),
 * the loop proceeds to the next replica. Only surfaces the I/O
 * error if every replica fails AND no replica produced a csum
 * match.
 */
STM_MUST_USE
stm_status stm_sync_mirror_read(stm_sync *s, const uint64_t paddrs[],
                                   size_t n, void *buf, size_t len,
                                   const uint8_t expected_csum[32]);

/*
 * P5-4b-ii-α: evacuate one allocated range from `target_device_id`
 * onto `survivor_device_id`.
 *
 * The target must be in STM_DEV_STATE_EVACUATING (set by
 * stm_pool_begin_evacuation). The survivor must be ONLINE with an
 * attached alloc and must not be the target. Each call:
 *   1) picks the lowest-start allocated range on the target's alloc
 *      tree (stm_alloc_first_allocated);
 *   2) reads length_blocks × STM_UB_SIZE bytes from the target bdev;
 *   3) reserves `length_blocks` on the survivor's alloc;
 *   4) writes the bytes + fsyncs the survivor;
 *   5) frees the range from the target's tree (marks PENDING so the
 *      next sync_commit sweeps it per allocator.tla).
 *
 * The entire step runs under sync's lock so the read / reserve /
 * write / free sequence is atomic w.r.t. other sync callers. At the
 * spec level (v2/specs/evac.tla), this corresponds to EvacuateAtomic:
 * replicas[b] = (replicas[b] \ {target}) ∪ {survivor} in one step.
 *
 * The caller owns survivor selection because at this layer we cannot
 * see which devices already hold OTHER replicas of the block: picking
 * a survivor that happens to already hold b would collapse two
 * replicas onto one device (violating evac.tla's `s \notin
 * replicas[b]` precondition). Caller derives the survivor from its
 * bptr / replica-list: any device except target and except the
 * current holders of b.
 *
 * The caller MUST call stm_sync_commit to persist the migration (the
 * survivor reservation + target free both live in in-RAM alloc state
 * until then). Crash between evacuation_step and commit loses the
 * survivor write (block is still on target) — safe but wasted work.
 *
 * On STM_OK, `*out_old_paddr` and `*out_new_paddr` are populated.
 * Any higher-layer reference to *out_old_paddr must be rewritten to
 * *out_new_paddr before the next sync_commit.
 *
 * Returns:
 *   STM_OK        — one range evacuated; paddrs populated.
 *   STM_ENOENT    — target alloc tree has no live allocated entries
 *                    (tree empty or all PENDING). Caller finalizes via
 *                    stm_pool_finish_evacuation + sync_commit.
 *   STM_EINVAL    — target not EVACUATING, survivor not ONLINE or is
 *                    the target, out-of-range ids, shape errors.
 *   STM_EROFS     — pool opened read_only.
 *   STM_EWEDGED   — sync handle wedged (post-quorum-loss state).
 *   STM_EQUORUM / STM_EIO / STM_ENOMEM — backend failures; no state
 *                    change on target's tree (rolled back).
 */
STM_MUST_USE
stm_status stm_sync_evacuation_step(stm_sync *s, uint16_t target_device_id,
                                       uint16_t survivor_device_id,
                                       uint64_t *out_old_paddr,
                                       uint64_t *out_new_paddr);

/*
 * R17 P1-2 safe wrapper over stm_pool_remove_device. Verifies the
 * target's alloc tree is drained (no ALLOCATED entries) before
 * flipping the slot to REMOVED. Callers that skip evacuation on a
 * data-bearing device would silently violate evac.tla's
 * NoTargetReplicasAfterComplete; this wrapper returns STM_EBUSY
 * instead.
 *
 * Returns:
 *   STM_OK             — slot flipped to REMOVED.
 *   STM_EBUSY          — target has allocated data; call
 *                         stm_pool_begin_evacuation → evacuation_step
 *                         loop → stm_sync_finish_evacuation.
 *   STM_ENOTSUPPORTED  — device_id == 0 (metadata primary; P5-4c).
 *   STM_EINVAL / STM_EROFS — as for stm_pool_remove_device.
 */
STM_MUST_USE
stm_status stm_sync_remove_device(stm_sync *s, uint16_t device_id,
                                     size_t redundancy_floor);

/*
 * R17 P2-5 safe wrapper over stm_pool_finish_evacuation. Verifies
 * the target's alloc tree is drained, then finalizes the EVACUATING
 * → REMOVED transition via the pool primitive, then detaches the
 * target's alloc handle from sync's internal table (s->allocs[X] =
 * NULL) so subsequent sync_commit loops skip it.
 *
 * **Ownership semantics (R18 P2-4)**: on STM_OK, the `stm_alloc *`
 * previously attached via `stm_sync_attach_alloc` is DETACHED from
 * sync but NOT closed. Ownership reverts to the caller. The caller
 * MUST close the alloc (stm_alloc_close) BEFORE closing the device's
 * underlying `stm_bdev`, and MUST NOT perform any further alloc
 * operation (commit / reserve / free / lookup) on it — the alloc's
 * cached bdev pointer targets the now-removed device, so any bdev
 * I/O against it is UB from the pool's perspective.
 *
 * In practice most callers pair finish_evacuation with alloc_close
 * immediately:
 *
 *     if (stm_sync_finish_evacuation(s, id) == STM_OK) {
 *         stm_alloc_close(attached_alloc_for_id);
 *     }
 *
 * Returns:
 *   STM_OK             — slot flipped to REMOVED; alloc detached.
 *                         Caller owns the detached alloc; close it.
 *   STM_EBUSY          — target tree still has allocated ranges
 *                         (more evacuation_step calls needed).
 *   STM_EINVAL         — slot not EVACUATING or out-of-range.
 *   STM_EROFS          — RO pool.
 */
STM_MUST_USE
stm_status stm_sync_finish_evacuation(stm_sync *s, uint16_t device_id);

/*
 * P5-4c-α: ONLINE → ONLINE device replacement. Composes add_device +
 * begin_evacuation + evacuation_step* + finish_evacuation + intervening
 * commits, returning STM_OK only after the full sequence durably
 * lands. Drives the exact pattern any application would write by
 * hand — bundled for correctness + audit focus.
 *
 * Pre:
 *   - `old_device_id != 0` (R17 P1-1: metadata primary guarded).
 *   - Slot at `old_device_id` is ONLINE. (FAULTED → new reconstruct
 *     is a distinct primitive — P5-4c-β, needs bptr-layer iteration.
 *     Returns STM_ENOTSUPPORTED here.)
 *   - `new_device` / `new_alloc` are a fresh pair the caller owns.
 *     `new_device->bdev` valid. `new_alloc` must be freshly created
 *     (empty tree, root_paddr=0) — the wrapper stamps its device_id
 *     internally to match the actual slot it lands at (caller cannot
 *     predict the slot under concurrent callers).
 *   - Pool has headroom: device_count < STM_POOL_DEVICES_MAX.
 *
 * Sequence:
 *   1. stm_pool_add_device(new_device)        — new device appended.
 *   2. stm_sync_attach_alloc(new_slot, new_alloc).
 *   3. stm_sync_commit                          — persists ADD.
 *   4. stm_pool_begin_evacuation(old, floor).
 *   5. stm_sync_commit                          — persists EVACUATING.
 *   6. Loop: stm_sync_evacuation_step(old, new_slot, ...) until
 *      STM_ENOENT.
 *   7. stm_sync_commit                          — persists migrations.
 *   8. stm_sync_finish_evacuation(old)         — EVACUATING → REMOVED.
 *   9. stm_sync_commit                          — persists REMOVED.
 *
 * **Recovery semantics (R19 + R22)**:
 * - Failure BEFORE step 1's pool mutation (wedged/RO guards, old not
 *   ONLINE, etc): nothing durable or in-RAM-mutated. Retry freely.
 * - Failure AT step 1 (`stm_pool_add_device_locked`): the mutation
 *   didn't take effect. Retry with the same or different args.
 * - Failure AT step 2a/2b (set_device_id / attach_alloc): step 1's
 *   add is rolled back via `replace_rollback_or_wedge`. Retry.
 * - Failure AT step 3 (first sync_commit): in-RAM roster has new
 *   slot at ONLINE with new_alloc attached; old_device_id still
 *   ONLINE; no durable progress.  **R22 resume path**: retry
 *   with the same `new_device` and `new_alloc` succeeds. The wrapper
 *   detects the UUID+alloc-identity match and skips steps 1+2a+2b.
 *   See the "Resume criterion" paragraph below for its semantics.
 * - Failure AFTER step 3 commit + BEFORE step 5 (EVACUATING durable):
 *   symmetric to step-3 failure — the wrapper still detects the
 *   added slot and retries from step 3.
 * - Failure AFTER step 5 (old is EVACUATING on disk): retry
 *   supported via the R19 EVACUATING-resume path. Re-invoke with
 *   same `old_device_id` + same `new_alloc`; the wrapper detects
 *   EVACUATING + already-attached alloc and resumes from step 6.
 *
 * **Resume criterion** (R22 P3-2 / P3-5 — clarifies the "retry with
 * same args" contract):
 *
 * The resume detection checks ONLY (a) UUID match and (b) alloc-
 * identity match against the attached slot. Other fields in
 * `new_device` (role, class_, state) and the `old_device_id` /
 * `redundancy_floor` arguments are NOT compared against the prior
 * failed call. Concretely:
 *
 * - Changing `new_device->role` / `class_` on retry: silently
 *   ignored (the step-1 add stamped role/class once; they persist
 *   in the roster and are not re-stamped on resume).
 * - Changing `old_device_id` on retry: the retry runs steps 4-9
 *   against the NEW old, not the one the prior failed call named.
 *   If the user mistypes `old_device_id`, the retry replaces a
 *   different device than originally intended.
 * - Changing `redundancy_floor`: used by step 4 (begin_evacuation);
 *   the retry uses the new value.
 *
 * Callers that need strict "retry replays exactly the prior call"
 * semantics must track their own retry cookie at the admin layer.
 * The wrapper's contract is: "given a new_alloc already attached
 * at an ONLINE slot, finish the replace as specified by the
 * current call's old_device_id + redundancy_floor."
 *
 * **Slot-0 refusal (R22 P3-1)**: the resume path refuses to target
 * slot 0 (the metadata primary). A caller whose `new_device->uuid`
 * happens to equal device 0's UUID and whose `new_alloc` equals
 * `s->allocs[0]` cannot use this function to drain data onto the
 * primary. Returns STM_EEXIST. Symmetric with
 * `stm_sync_attach_alloc`'s "primary is fixed" rule.
 *
 * **Concurrent-caller protection (P5-8 + R23 P1-1 / P2-3)**: the
 * partial in-RAM state across a failed step-3 (or step-5) and the
 * subsequent retry is protected by a per-pool replace-in-flight
 * claim.  While the claim is held on `new_slot`:
 *
 *   - Public pool mutators on `new_slot` refuse STM_EBUSY:
 *     `stm_pool_remove_device`, `stm_pool_begin_evacuation`,
 *     `stm_pool_finish_evacuation`, `stm_pool_fail_device`,
 *     `stm_pool_rejoin_device`.  `stm_pool_add_device` refuses
 *     while ANY claim is held.
 *   - The `_locked` pool variants bypass — replace's own internal
 *     ops use them, so the wrapper can proceed past its own
 *     guard.  The sync-layer safe wrappers
 *     (`stm_sync_remove_device`, `stm_sync_finish_evacuation`)
 *     also use `_locked` variants; callers MUST NOT invoke those
 *     on `new_slot` while a replace is in flight, or the partial
 *     state will be torn down behind the replace.
 *
 * Resume detection + claim acquisition are atomic under one
 * pool.wrlock + sync.lock CS (R23 P1-1), so a concurrent
 * `stm_sync_remove_device(new_slot)` cannot land between detection
 * and claim-set.  The claim persists across failed-call → retry
 * windows (idempotent same-slot reclaim on retry); released only
 * on full success of step 9.
 *
 * **Alloc ownership after OK**: the OLD device's alloc (attached via
 * `stm_sync_attach_alloc` before this call) is detached on success
 * (via the internal `stm_sync_finish_evacuation`); the caller owns
 * it and MUST `stm_alloc_close` it before closing the old device's
 * bdev. The NEW device's alloc stays attached at `*out_new_device_id`
 * until the caller explicitly detaches (via another finish_evacuation)
 * or closes the sync handle.
 *
 * Slot semantics (caveat): `new_slot` is a NEW roster index, not a
 * reuse of `old_device_id`. `old_device_id` becomes a REMOVED
 * tombstone; `new_device`'s UUID occupies a fresh slot. For a true
 * "swap into old's slot" variant (ARCH §4.7.3 full intent), slot
 * reuse requires either burning the old UUID entirely or a dedicated
 * refactor — deferred.
 *
 * `*out_new_device_id` receives the new slot index (if non-NULL).
 *
 * Returns:
 *   STM_OK             — replacement complete + durable.
 *   STM_ENOTSUPPORTED  — old slot FAULTED (reconstruct path unimplemented)
 *                         or old_device_id == 0.
 *   STM_EINVAL         — shape / state errors.
 *   STM_EBUSY          — another slot is EVACUATING.
 *   STM_ENOSPC         — roster at STM_POOL_DEVICES_MAX.
 *   STM_EEXIST         — new_device->uuid collides with roster.
 *   STM_EROFS          — RO pool.
 *   STM_EWEDGED        — sync handle wedged (either before call, or
 *                         wedged during this call because a rollback
 *                         itself failed; R19 P2-2).
 *   STM_ECORRUPT       — drain loop exceeded STM_REPLACE_DRAIN_MAX_STEPS
 *                         without converging (100M steps cap; R19 P2-5).
 */
STM_MUST_USE
stm_status stm_sync_replace_device_online(
    stm_sync *s, uint16_t old_device_id,
    const stm_pool_device *new_device,
    stm_alloc *new_alloc,
    size_t redundancy_floor,
    uint16_t *out_new_device_id);

/* ========================================================================= */
/* Per-dataset key management (P4-4c).                                        */
/* ========================================================================= */

/*
 * Maximum valid `dataset_id` for every sync-layer key API. Mirrors
 * the janus qid-path dataset field's 28-bit range so a pool created
 * via keyfile-only mode stays mountable via janus on a different
 * host. Values above this are refused STM_ERANGE at the FS boundary.
 */
#define STM_SYNC_DATASET_ID_MAX   UINT64_C(0x0FFFFFFF)

/*
 * Add a new dataset with a freshly-generated DEK. Inserts
 * (dataset_id, key_id=0, CURRENT) into the key-schema sub-tree and
 * stashes the plaintext DEK in the in-RAM map.
 *
 * Exactly one of {wk, janus} must be non-NULL (mirrors stm_sync_open).
 * For the keyfile path, `stm_sync` uses libsodium CSPRNG to generate
 * the DEK and `stm_hybrid_wrap` to produce the wrapped blob. For the
 * janus path, the daemon's CSPRNG is the DEK source and the backend's
 * wrap fn produces the wrapped blob; see `stm_janus_client_rotate`.
 *
 * `dataset_id == 0` is reserved for the pool's metadata key and is
 * refused here (STM_EINVAL). The metadata key is installed by
 * `stm_sync_create` during formatting.
 *
 * Returns STM_EEXIST if a CURRENT entry already exists for
 * `dataset_id` (use `stm_sync_rotate_dataset_key` to advance key_id).
 */
STM_MUST_USE
stm_status stm_sync_add_dataset_key(stm_sync *s,
                                      uint64_t dataset_id,
                                      const stm_hybrid_keys *wk,
                                      struct stm_janus_client *janus,
                                      uint64_t *out_new_key_id);

/*
 * Rotate a dataset's key (ARCH §7.7.2). Generates a new DEK, wraps
 * it, and atomically inserts (dataset_id, new_key_id, CURRENT) +
 * retires the existing CURRENT entry in one schema mutation. The
 * change becomes durable on the next `stm_sync_commit`.
 *
 * Exactly one of {wk, janus} must be non-NULL.
 *
 * `dataset_id == 0` (pool metadata key) is refused — rotating it
 * would leave existing metadata nodes un-decryptable. Metadata-key
 * rotation (with an accompanying re-encrypt sweep) is future work.
 *
 * The old DEK stays resident in the sync handle's RAM so readers of
 * data encrypted under it can still decrypt. It is removed only by
 * `stm_sync_keyschema_sweep` (RETIRED → PRUNING → deleted).
 *
 * On success, `*out_new_key_id` and `*out_old_key_id` are populated.
 */
STM_MUST_USE
stm_status stm_sync_rotate_dataset_key(stm_sync *s,
                                         uint64_t dataset_id,
                                         const stm_hybrid_keys *wk,
                                         struct stm_janus_client *janus,
                                         uint64_t *out_new_key_id,
                                         uint64_t *out_old_key_id);

/*
 * Sweep every RETIRED key for `dataset_id`, transitioning each
 * through PRUNING and deleting it. In-RAM DEKs for the pruned entries
 * are wiped. Phase 4 has no extent layer referencing these keys, so
 * the sweep is always safe; Phase 6's extent manager will own the
 * refcount check before calling this API.
 *
 * On success, `*out_pruned_count` is set to the number of retired
 * keys pruned. STM_OK on empty sweeps (no retired entries — result
 * is idempotent).
 *
 * Like rotate/add, the on-disk change lands on the next commit.
 */
STM_MUST_USE
stm_status stm_sync_keyschema_sweep(stm_sync *s,
                                      uint64_t dataset_id,
                                      size_t *out_pruned_count);

/*
 * Look up a DEK by (dataset_id, key_id). Copies 32 bytes into
 * `out_dek`. Returns STM_ENOENT if the key is not present in the
 * in-RAM map (never generated, never unwrapped, or swept away).
 *
 * Primarily used by tests and by the extent layer (Phase 6) to pick
 * the right DEK for reads of extents that carry the key_id in their
 * AD struct.
 */
STM_MUST_USE
stm_status stm_sync_get_dek(const stm_sync *s,
                              uint64_t dataset_id, uint64_t key_id,
                              uint8_t out_dek[32]);

/*
 * Number of DEKs currently held in the in-RAM map (across all
 * datasets + key_ids). Tests use this to confirm rotations add and
 * sweeps remove the expected counts.
 */
size_t stm_sync_dek_count(const stm_sync *s);

/* Forward decls for index accessors below. */
struct stm_dataset_index;  typedef struct stm_dataset_index  stm_dataset_index;
struct stm_snapshot_index; typedef struct stm_snapshot_index stm_snapshot_index;

/*
 * P6-persist: borrowed handles on the sync-owned dataset + snapshot
 * indices. Lifetime is the sync handle's — caller MUST NOT close them.
 * Both are non-NULL post-sync_create / post-sync_open.
 *
 * The dataset index always has the root dataset (id=1) populated (fresh
 * pool: from sync_create's seed; mounted pool: from on-disk via
 * stm_dataset_index_load_at).  The snapshot index is empty on a fresh
 * pool, populated from on-disk on a mounted pool.
 *
 * Mutations made on these indices between sync_open and sync_close
 * persist on the next sync_commit (which calls _commit on each handle).
 *
 * **Concurrency contract (R31 P1-1):** the dataset/snapshot indices
 * have their own internal mutexes; their public mutators are
 * thread-safe with respect to each other. They are NOT, however,
 * coordinated with stm_sync's internal commit/retry state machine.
 * A caller that mutates an index while stm_sync_commit is in flight,
 * or between consecutive stm_sync_commit calls that retry on
 * STM_EQUORUM, can introduce content divergence at the same target_gen
 * across devices, violating quorum.tla::ContentQuorumAtGen. Pattern
 * to follow: serialize index mutations against commit at the
 * application layer (e.g., a single "fs writer" thread that owns the
 * sync handle), or quiesce all mutators before invoking
 * stm_sync_commit and until it returns success (or the operator
 * abandons after STM_EQUORUM). Internal Stratum modules (alloc,
 * keyschema) avoid this hazard by mutating only through stm_sync
 * APIs that take s->lock; dataset/snapshot mutations bypass s->lock.
 */
stm_dataset_index  *stm_sync_dataset_index(stm_sync *s);
stm_snapshot_index *stm_sync_snapshot_index(stm_sync *s);

/*
 * P7-3: extent-index handle. Same lifetime + thread-safety contract
 * as the dataset / snapshot accessors above.
 */
struct stm_extent_index;
typedef struct stm_extent_index stm_extent_index;
stm_extent_index *stm_sync_extent_index(stm_sync *s);

/*
 * P7-15: repair-log index handle. Same lifetime + thread-safety
 * contract as the other index accessors above. Production callers
 * never emit directly — entries are appended by the scrub β
 * verify-callback (`sync_scrub_verify_cb`) on every successful
 * Phase-3 rewrite. Tests can reach the handle to inspect the in-
 * RAM list or drive `stm_repair_log_index_emit` synthetically;
 * any emit persists on the next `stm_sync_commit`.
 */
struct stm_repair_log_index;
typedef struct stm_repair_log_index stm_repair_log_index;
stm_repair_log_index *stm_sync_repair_log_index(stm_sync *s);

/*
 * P7-CAS: CAS-tier index handle. Same lifetime + thread-safety contract
 * as the other index accessors above. The CAS index is owned by sync
 * and persists across commits via the lifecycle wiring; migration /
 * rehydration paths (the future P7-CAS-2 chunk) will operate on it
 * via the higher-level stm_sync_migrate_to_cold / _rehydrate APIs.
 */
struct stm_cas_index;
typedef struct stm_cas_index stm_cas_index;
stm_cas_index *stm_sync_cas_index(stm_sync *s);

/*
 * P7-CAS-5: trigger one CAS auto-GC sweep cycle out-of-band from
 * `stm_sync_commit`. Takes `sync->lock` internally; safe to call
 * from any context that does NOT already hold sync->lock (notably:
 * scrub orchestrators, periodic timers, manual-trigger fs-level
 * APIs).
 *
 * The sweep walks the cas-index for refcount=0 entries and reclaims
 * them via the same two-phase shape `stm_sync_commit` uses (cas_gc
 * first → alloc_free per paddr; FAULTED/REMOVED-device skip;
 * STM_EBUSY/ENOENT skip-clean on concurrent ref/gc). Reclaimed
 * paddrs go to PENDING with `free_gen = s->current_gen` (the
 * NEXT-target gen — sync_commit advances current_gen to target+2
 * post-commit, so between commits this reads as the next commit's
 * target). The alloc-tree sweep predicate is
 * `free_gen < committed_gen`; with free_gen = NEXT_target and the
 * next commit at committed_gen = NEXT_target, the predicate is
 * false → entries persist. The commit AFTER that
 * (`committed_gen = NEXT_target + 2`) satisfies the predicate and
 * reclaims them. Same delay-by-one-cycle cadence as the in-commit
 * invocation.
 *
 * Use cases:
 *   - Scrub-driver orchestrators that interleave `stm_scrub_step`
 *     with cas-gc so cold-tier reclamation keeps pace with scrub
 *     passes (the natural place for periodic invocation).
 *   - Manual triggers from a `/ctl/.../cas-gc` admin path.
 *   - Test harnesses that want to exercise sweep behavior without
 *     waiting for a sync_commit.
 *
 * Returns:
 *   STM_OK         — sweep ran (possibly with zero entries).
 *   STM_EWEDGED    — fs is wedged; sweep refused.
 *   STM_EROFS      — fs is read-only; sweep refused (CAS GC
 *                    mutates alloc state which is RW-only).
 *   STM_EINVAL     — NULL `s`.
 *   other          — first per-tuple non-OK status (idempotent
 *                    retry: re-call to resume after transient
 *                    failures).
 *
 * Spec: cas.tla::GC (atomic remove-and-mark-freed). The semantics
 * are identical whether invoked from `stm_sync_commit` or from
 * this entry point — the cas_idx.lock per-call serialization
 * ensures no race window between observation of refcount=0 and
 * entry removal.
 */
STM_MUST_USE
stm_status stm_sync_cas_gc_sweep(stm_sync *s);

/* Forward decl for stm_sync_scrub_install_production_cb below. The
 * full type lives in <stratum/scrub.h>; including it here would create
 * a cycle (scrub.h includes types.h which already pulls sync's deps).
 */
struct stm_scrub;
typedef struct stm_scrub stm_scrub;

/*
 * P7-CAS-6: scrub-orchestrator wrapper. Drives one `stm_scrub_step`
 * call and, if the step transitions the scrub state from RUNNING to
 * COMPLETED, fires `stm_sync_cas_gc_sweep(s)` to reclaim refcount=0
 * CAS entries accumulated during the just-finished pass. This keeps
 * cold-tier reclamation in pace with scrub passes — the natural
 * cadence for an orchestrator that already drives scrub.
 *
 * Semantics:
 *   - Pre-step: capture scrub state via `stm_scrub_status_get`.
 *   - Call `stm_scrub_step(sc)`. Return its status if non-OK; the
 *     sweep is NOT fired in that case (scrub failure is the
 *     load-bearing signal).
 *   - Post-step: capture state again. If pre==RUNNING and
 *     post==COMPLETED, the pass just finished — fire the sweep.
 *   - The sweep's status is reported via `*out_cas_gc_err` (best-
 *     effort: a sweep error doesn't promote to the wrapper's return
 *     value, since the scrub step itself succeeded). Pass NULL to
 *     suppress.
 *
 * Lock posture: each underlying call takes its own locks
 * sequentially; no nested holding. `stm_scrub_step` takes
 * `sc->lock + pool->rdlock`; `stm_scrub_status_get` takes
 * `sc->lock` briefly; `stm_sync_cas_gc_sweep` takes
 * `pool.rdlock + sync.lock`. All released between calls — no
 * lock-graph cycle.
 *
 * **Single-driver assumption (R57 P3-1 + P3-2)**: this wrapper
 * assumes the orchestrator is the sole caller of
 * `stm_scrub_start` / `stm_scrub_pause` / `stm_scrub_reset` on
 * `sc` for the lifetime of the scrub run. A concurrent
 * `stm_scrub_reset` or `stm_scrub_start` between the wrapper's
 * `stm_scrub_step` return and the post-status read can shift
 * the observed state to IDLE / RUNNING respectively, missing
 * the RUNNING→COMPLETED transition the wrapper relies on. The
 * miss is idempotent — the next `stm_sync_commit`'s in-commit
 * sweep reclaims the same refcount=0 entries — but the cadence
 * benefit of scrub-driven sweeping is lost for that pass. If
 * shared-sc orchestration is needed, a sticky completion-signal
 * mechanism on the scrub side would be the principled fix
 * (deferred).
 *
 * Returns:
 *   STM_OK     — step ran (possibly with sweep also firing); check
 *                `*out_cas_gc_err` for sweep status.
 *   STM_EINVAL — NULL `s` or `sc`. `*out_cas_gc_err` is set to
 *                STM_OK before the NULL check (uniform contract:
 *                the out-param always reflects "no sweep error"
 *                when the wrapper returns; on STM_EINVAL the
 *                wrapper hasn't run, so STM_OK is the right
 *                placeholder).
 *   other      — passthrough from `stm_scrub_step` or
 *                `stm_scrub_status_get`. Sweep not fired.
 *
 * Use cases:
 *   - Production scrub-runner orchestrators (the main use case).
 *   - Test harnesses that want to drive a scrub pass and observe
 *     CAS reclamation in lockstep.
 *
 * Direct callers of `stm_scrub_step` who don't want the auto-sweep
 * behavior can continue to use `stm_scrub_step` directly + invoke
 * `stm_sync_cas_gc_sweep` on their own cadence.
 */
STM_MUST_USE
stm_status stm_sync_scrub_step_with_cas_gc(stm_sync *s, stm_scrub *sc,
                                              stm_status *out_cas_gc_err);

/*
 * P7-4: POSIX-shape extent write/read with full COW routing.
 *
 * `stm_sync_write_extent` reserves blocks for a fresh extent,
 * AEAD-encrypts the plaintext, writes ciphertext+tag to disk,
 * inserts the extent record, and routes any dropped paddrs through
 * the snapshot dead-list (extent.tla::Overwrite + dead_list.tla::
 * OverwriteBlock + allocator.tla::Free composition).
 *
 * `stm_sync_read_extent` looks up the extent covering `off`, reads
 * ciphertext+tag, AEAD-decrypts, and copies `len` bytes to the
 * caller. Holes (no extent) return zeros.
 *
 * MVP constraints (P7-4):
 *   - len > 0, multiple of 4 KiB, ≤ 128 KiB (recordsize default).
 *   - off must be 4 KiB aligned.
 *   - Single-extent per call: caller iterates for spans > recordsize.
 *
 * P7-10: encryption uses the dataset's CURRENT DEK from the
 * keyschema. The write path resolves (key_id, DEK) for `dataset_id`
 * via the in-RAM DEK map (populated at sync_open by the unwrap iter
 * + sync_create's auto-install of root and pool DEKs); encrypts
 * under the DEK; stamps key_id on the extent record. Read path
 * looks up DEK by the extent's stamped key_id, so RETIRED keys
 * still decrypt their original extents. Pre-P7-10 used the per-
 * pool `metadata_key` for every dataset's data; the new behaviour
 * gives proper key isolation + enables key rotation. Datasets
 * whose CURRENT DEK is missing (caller forgot to call
 * stm_sync_add_dataset_key on a non-root dataset) get STM_ENOENT
 * from write_extent.
 *
 * Thread safety: serialized by sync's internal mutex. Composes with
 * sync_commit's idempotent persistence — every commit captures all
 * writes since the prior commit.
 */
STM_MUST_USE
stm_status stm_sync_write_extent(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                    uint64_t off, const void *buf, size_t len);

STM_MUST_USE
stm_status stm_sync_read_extent(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                   uint64_t off, void *buf, size_t len,
                                   size_t *out_read);

/*
 * P7-9: POSIX-shape truncate. Shrinks (dataset_id, ino) to `new_size`
 * bytes.
 *
 * Drops every live extent whose `off >= new_size`. If exactly one
 * extent crosses the boundary (`off < new_size < off+len`), it is
 * SHRUNK to `[off, new_size)` by reading + decrypting its full
 * plaintext, slicing to the kept prefix, and re-encrypting the
 * prefix under a FRESH (paddr_0, current_gen) AEAD nonce — the
 * original extent's replica paddrs flow through dead-list / free
 * per the COW path. Re-encrypting under fresh paddrs prevents
 * `(paddr, gen)` reuse: the original extent's full ciphertext and
 * the new shrunk-prefix's plaintext would otherwise share a nonce.
 * Spec: `extent.tla::Truncate`.
 *
 * MVP constraints:
 *   - `new_size` must be a multiple of `STM_UB_SIZE` (4 KiB blocks).
 *     Non-aligned truncate would require partial-block read+modify+
 *     write at the underlying bdev, deferred.
 *   - **P7-11**: holds the sync handle's internal lock across all
 *     three phases (lookup → read+re-encrypt → past-extent drop +
 *     drop-route). This makes truncate atomic w.r.t. concurrent
 *     `stm_sync_commit` and `stm_sync_write_extent` — closes
 *     **R41 P3-1 case (a)** (concurrent commit between Phase 2 and
 *     Phase 3) and **R41 P3-2** (same gap, scrub-flavored).
 *   - **P7-12**: pre-allocates Phase 3's working buffers (drop_idx
 *     + paddrs) BEFORE Phase 2's overwrite, via `stm_extent_truncate_
 *     peek`. Phase 3 then calls `stm_extent_truncate_into` which
 *     never allocates, so it cannot fail with STM_ENOMEM. Closes
 *     **R41 P3-1 case (b)** (Phase 3 alloc failure leaves Phase 2's
 *     prefix-shrink committable): on pre-alloc ENOMEM, Phase 2 has
 *     not yet run and the index is unchanged.
 *   - Trade-off: longer lock-hold duration (decrypt + encrypt +
 *     bdev I/O all under s->lock); for the 128 KiB recordsize
 *     default this is acceptable. Cascade: scrub's verify cb takes
 *     s->lock briefly to look up the per-extent DEK, so concurrent
 *     truncate extends scrub-step latency by the same window (no
 *     deadlock — lock-graph stays acyclic).
 *   - Concurrent-write atomicity (POSIX truncate-vs-write at the FS
 *     boundary) remains the caller's responsibility — Stratum's sync
 *     layer doesn't model the FS-layer file-handle locks that POSIX
 *     specifies.
 *   - Per-paddr drop-route on Phase 3 is best-effort (R36 P1-1 /
 *     P2-1): a failed `sync_drop_paddr_locked` for a single paddr
 *     surfaces as the function's return value but doesn't abort the
 *     overall truncate — other paddrs continue to drop-route. A
 *     leaked paddr is not a corruption hazard (it's still allocated
 *     in the bitmap; future fsck reconciles).
 *
 * Returns:
 *   STM_OK             — truncate complete.
 *   STM_EINVAL         — bad args (NULL s; ds/ino == 0; new_size
 *                         not block-aligned).
 *   STM_EWEDGED        — sync wedged.
 *   STM_EROFS          — read-only.
 *   STM_ENOMEM / STM_EIO / STM_EBADTAG / ... — bubbled from the
 *                         underlying read+write of the crossing extent
 *                         or the alloc/bdev layer.
 */
STM_MUST_USE
stm_status stm_sync_truncate(stm_sync *s, uint64_t dataset_id, uint64_t ino,
                                uint64_t new_size);

/*
 * P7-16: stm_sync_reflink — POSIX-shape FICLONE at the sync layer.
 * Replaces dst's empty extent tree with a reflink-share of src's
 * extent tree. For each (src_dataset_id, src_ino) extent E, this
 * inserts a sibling extent at (dst_dataset_id, dst_ino, E.off,
 * E.len, E.replicas, E.gen, E.key_id) with origin INHERITED from E
 * (so AEGIS-256 verify succeeds for both siblings reading the shared
 * ciphertext). Allocator refcounts on the shared paddrs are bumped
 * once per replica per src extent — when one side is later COW'd
 * the allocator's `stm_alloc_free` decrements; when the refcount
 * reaches zero (last reference dropped), the paddr is reclaimed.
 *
 * Same-dataset reflinks only at v1 MVP. Cross-dataset reflinks
 * require both datasets to share an encryption key; deferred per
 * ARCH §11.12.3.
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - src and dst are the same (ds, ino) (STM_EINVAL — no self-reflink).
 *   - dataset_id is not the same for src and dst (STM_EXDEV — cross-
 *     dataset reflinks deferred to a future chunk).
 *   - dst_ino has any extent (STM_EEXIST — caller MUST clear dst first;
 *     truncate to 0 plus re-create is the typical pattern but in MVP
 *     we just refuse).
 *   - Any allocator refcount-bump fails (STM_ECORRUPT — should never
 *     happen for live extents; rolls back any prior bumps).
 *   - Wedged or read-only (standard guards).
 *
 * Atomicity: holds sync->lock across all extent-tree mutations and
 * refcount bumps. On partial failure, every successful refcount bump
 * is rolled back via stm_alloc_free + every successful extent-tree
 * insert is removed via stm_extent_delete_file (delete_file is the
 * cheapest "drop everything for this dst_ino" given dst_ino was
 * required to be empty at entry).
 *
 * Models extent.tla::Reflink iterated over every (src_dataset_id,
 * src_ino) extent; lock-graph: sync.lock OUTER → extent_idx.lock +
 * per-device alloc.lock INNER. fs->lock is the outermost layer when
 * called via stm_fs_reflink (P7-16's public surface).
 */
STM_MUST_USE
stm_status stm_sync_reflink(stm_sync *s,
                              uint64_t src_dataset_id, uint64_t src_ino,
                              uint64_t dst_dataset_id, uint64_t dst_ino);

/*
 * P7-CAS-2: stm_sync_migrate_to_cold — POSIX-shape "make this file
 * cold" at the sync layer. Walks every HOT extent at (ds, ino) and
 * converts each to a COLD extent that references a CAS chunk:
 *
 *   For each hot extent E:
 *     1. Read E's plaintext (decrypt under the dataset's DEK at the
 *        AEAD AD reconstructed from E.origin_*).
 *     2. BLAKE3-256(plaintext) → content_hash.
 *     3. CAS lookup the hash:
 *        HIT  : bump CAS refcount on the existing entry.
 *        MISS : reserve fresh hot-side replica paddrs, AEAD-encrypt
 *               the plaintext under CAS AD = (pool_uuid, content_hash)
 *               onto the fresh paddrs, write the ciphertext + tag,
 *               insert a new CAS index entry. (HotColdReplicasDisjoint
 *               is enforced by allocator-issued fresh paddrs +
 *               cas.tla::CASReplicasDisjoint scan inside stm_cas_insert
 *               — closes R49 P2-1 forward-note.)
 *     4. Atomically swap the HOT extent for a COLD extent at the same
 *        (ds, ino, off, len) referencing content_hash. (
 *        stm_extent_migrate_to_cold preserves NoOverlapWithinIno.)
 *     5. Drop-route the source HOT extent's replicas via
 *        sync_drop_paddr_locked (refcount-aware: reflink-shared paddrs
 *        DecRef; otherwise dead-list / alloc_free).
 *
 * Atomicity: holds sync->lock across every (ds, ino) extent's
 * migration. Concurrent stm_sync_write_extent / commit / scrub on a
 * different (ds, ino) is unaffected; same (ds, ino) write/read
 * serializes behind us. On a per-extent failure (read-decrypt error,
 * AEAD-encrypt error, CAS insert error, swap error), already-migrated
 * extents stay migrated (each per-extent migration is committed
 * before the next one starts). The caller can retry the whole call
 * to migrate the remaining extents — every step is idempotent at the
 * (ds, ino, off) granularity (re-hashing the same plaintext yields
 * the same hash; a CAS-hit just bumps refcount; the swap refuses if
 * the source is already COLD with STM_EINVAL — caller treats as
 * "already migrated" via STM_OK normalization).
 *
 * MVP constraints:
 *   - Same-dataset / same-pool only (CAS chunks shared across
 *     datasets is the dedup property; the per-dataset DEK does NOT
 *     bind CAS chunks — they encrypt under the pool metadata key per
 *     ARCH §7.6.3's CAS AD shape).
 *   - One BLAKE3 hash per HOT extent (extent-granularity dedup).
 *     FastCDC sub-chunking — slicing one HOT extent into multiple
 *     variable-size COLD chunks — is a P7-CAS-3+ refinement.
 *   - Snapshot interaction: snapshots that capture cold extents are
 *     NOT supported in P7-CAS-2 MVP (snap_idx doesn't track CAS
 *     hashes, so auto-GC may reclaim chunks still referenced by a
 *     snapshot's view). Future work integrates CAS hash refcounts
 *     with snap_idx.
 *
 * Refusals:
 *   - NULL s (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - Wedged or read-only (STM_EWEDGED / STM_EROFS).
 *   - Errors from stm_sync_read_extent_locked (decrypt failure,
 *     STM_EBADTAG, STM_ENOMEM, STM_EIO) bubble up — the partially-
 *     migrated state is durable across the failure (per-extent
 *     atomicity).
 *
 * Models cas.tla::MigrateToCold iterated over every (ds, ino) hot
 * extent; lock-graph: sync.lock OUTER → extent_idx.lock + cas_idx.lock
 * + per-device alloc.lock INNER. fs->lock is the outermost layer when
 * called via stm_fs_migrate_to_cold.
 */
STM_MUST_USE
stm_status stm_sync_migrate_to_cold(stm_sync *s,
                                       uint64_t dataset_id, uint64_t ino);

/*
 * P7-5: install the production scrub β verify-callback on `sc`.
 *
 * The cb resolves each `paddr` against `sync`'s extent index via
 * `stm_extent_lookup_by_paddr`:
 *
 *   - paddr matches a live extent's base → AEAD-decrypt the entire
 *     ciphertext+tag at that paddr (using the same nonce + AD shape as
 *     `stm_sync_write_extent`) and return STM_SCRUB_VERIFY_OK on
 *     success or STM_SCRUB_VERIFY_UNREPAIRABLE on AEAD-tag failure /
 *     bdev I/O error / transient resource shortfall. Replica
 *     reconstruction is not yet implemented — bptr.tla's full
 *     replica-walk + rewrite protocol awaits the replica-aware
 *     allocator and extent record extension. Until then, AEAD-tag
 *     failure means "no surviving redundancy" and the block is
 *     reported UNREPAIRABLE (matching bptr.tla's
 *     `NoOriginalOKMeansUnrepairable` corner).
 *
 *   - paddr does NOT match a live extent (mid-extent block, metadata
 *     tree node, bootstrap block, scrub durable region, etc.) →
 *     STM_SCRUB_VERIFY_OK. Mid-extent blocks are covered by the AEAD
 *     verify of the containing extent at its base. Non-extent
 *     allocated blocks (metadata, bootstrap) have no extent-level
 *     verify path in this MVP — operator-visible coverage is
 *     "extent-data only" until per-block-kind verify lands.
 *
 * Transient-error caveat (R37 P2-1): the cb does not distinguish
 * between persistent corruption (AEAD-tag failure on quiescent
 * data) and transient failures (`malloc` returning NULL,
 * `stm_bdev_read` returning STM_EIO, the device's bdev disappearing
 * mid-step). All five transient modes — `cbuf`/`pbuf` malloc fail,
 * bdev_read non-OK, NULL bdev from `stm_pool_device_bdev`, zero
 * `stm_aead_tag_len` — charge to STM_SCRUB_VERIFY_UNREPAIRABLE,
 * which is semantically a permanent data-loss attestation per ARCH
 * §7.16.2. Operators MUST NOT alert solely on `blocks_unrepairable`
 * — a near-OOM scrub run will libel healthy blocks. A future API
 * extension (transient outcome enum + separate counter) will give
 * operators a clean signal; until then, treat
 * `blocks_unrepairable` as a "investigate, don't auto-replace"
 * threshold.
 *
 * Concurrency (R37 P2-2): the cb does NOT acquire `sync->lock`. It
 * borrows `extent_idx`, `pool_uuid`, `metadata_key`, and `pool` as
 * immutable post-create state, plus `extent_idx`'s internal mutex
 * for the lookup. Concurrent `stm_sync_write_extent` /
 * `stm_sync_commit` activity during a `stm_scrub_step` call is
 * therefore permitted by the lock graph but is NOT race-free at
 * the data plane: a `(rec.paddr, rec.gen)` pair returned by the
 * lookup can become stale across a commit-promote-PENDING-then-
 * reuse boundary, with the cb's subsequent `stm_bdev_read`
 * observing the new ciphertext while attempting decrypt under
 * the old gen → false-positive UNREPAIRABLE. Callers MUST EITHER:
 * (a) quiesce all `stm_sync_write_extent` / `stm_sync_commit`
 * activity for the duration of every `stm_scrub_step` call, OR
 * (b) run scrub on a snapshot-mounted view that does not share
 * paddrs with live writes. Multi-writer harnesses without one
 * of these provisions can produce intermittent UNREPAIRABLE
 * phantoms uncorrelated with on-disk corruption.
 *
 * Lifetime contract: `sync` is borrowed (the cb's ctx) and MUST
 * outlive `sc`. Callers MUST close scrub BEFORE closing sync (per
 * scrub.h "Borrowed references"). Re-installing or clearing the cb
 * on `sc` follows the standard `stm_scrub_set_verify_cb` rules.
 *
 * Returns STM_EINVAL on NULL args; otherwise the
 * `stm_scrub_set_verify_cb` return code.
 */
STM_MUST_USE
stm_status stm_sync_scrub_install_production_cb(stm_sync *sync, stm_scrub *sc);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_H */
