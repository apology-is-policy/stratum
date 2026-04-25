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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_H */
