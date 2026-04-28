# Phase 7 — status and pickup guide

Authoritative pickup guide for Phase 7 (extent layer + cold tier
+ features). **Phase 7 ENTERED 2026-04-26** at `4eace52` after
Phase 6 namespace layer landed feature-complete (`a4add6d`).

ROADMAP §10 lists FastCDC + CAS + send/recv + reflinks as the §10.1
deliverables. Hot-tier extent records — the missing data layer
between datasets and stored bytes — are a P7 prerequisite that
ROADMAP §10 implicitly assumes; no §10 deliverable can land
without them. P7 entry begins with `extent.tla` and the
extent-module C impl.

This document also scaffolds the **P7 pre-work** that began in
parallel with Phase 6 — items that didn't depend on P6 deliverables
and were built independently of the namespace layer.

## P7 pre-work: FastCDC chunking (P6-independent)

ROADMAP §10.1 lists FastCDC under `src/cdc/` as a Phase 7
deliverable. The chunking algorithm itself has no P6 dependency
— it's a pure-function content-defined chunker. The integration
into the CAS tier (which DOES need P6) is a separate concern.

### Why pre-work is safe

- FastCDC is a deterministic algorithm operating on a byte stream.
- Output: chunk boundaries (offsets) + content hashes per chunk.
- No dependency on extents, datasets, snapshots, or CAS index.
- The library can be tested standalone with synthetic byte streams.

### Recommended scope for the pre-work chunk

- **Spec**: optional. FastCDC's correctness properties are
  testable rather than spec-needed (deterministic, shift-resistant
  per NOVEL #3, average chunk size ≈ target, min/max bounded).
  A cdc.tla spec could pin the shift-resistant property if
  desired; lower priority than other P6 specs.
- **Impl**: `v2/src/cdc/cdc.{h,c}` — FastCDC implementation per
  the canonical Yu/Yi/Zhang algorithm with Gear hashing. Configurable
  avg / min / max chunk size. NOVEL #3 mentions 8 MiB average as
  the default target.
- **Tests**: `v2/tests/test_cdc.c` — determinism (same input →
  same boundaries); shift-resistance (insert N bytes at start,
  verify > (1 - small_fraction) of post-shift chunk boundaries
  match the original); chunk-size distribution within bounds.
- **Reference doc**: new `v2/docs/reference/12-cdc.md` (numbering
  TBD depending on what Phase 6 adds first).

### NOT in scope for pre-work

- CAS index tree (needs bptr).
- Migration engine (needs dataset/extent infrastructure).
- Rehydration-on-write (touches the write path, depends on P6
  extent manager).

## Phase 7 status (overall)

- [x] **P7-CAS-4c snap_idx ↔ CAS hash refcount integration** —
      substantive `dbadc63` + R54 close
      `223250b` + hash-fixup (this commit). Closes the
      P7-CAS-2 forward-noted deferral: snapshots-with-cold-extents
      were unsupported because auto-GC could reclaim a chunk still
      referenced by a snap's tree_root view → STM_ECORRUPT on
      dangling-hash lookup. Fix: snap-aware deref routing for cold-
      record drops. New
      `stm_snapshot_index_overwrite_cold_block(idx, ds, hash,
      *out_should_deref)` mirrors the paddr-tier
      `stm_snapshot_index_overwrite_block` for the cold tier — if a
      most-recent PRESENT snap exists, append the hash to that
      snap's cold-dead-list and signal "no immediate deref"; else
      signal "caller derefs now". Wired into sync.c at the cold-
      record-drop bookends (write_extent + truncate post-deref
      bookend), replacing unconditional `stm_cas_deref` with snap-
      aware routing. Reflink + migrate rollback paths keep direct
      `stm_cas_deref` (records they JUST inserted; no snap captured
      them yet — orthogonal). Format break STM_UB_VERSION 18 → 19:
      snap value layout grows past the dead_paddrs[] tail with
      `cold_dead_count` (le32) + `cold_dead_hashes[N][32]`. New
      cap `STM_SNAP_COLD_DEAD_LIST_MAX = 256` (mirror of
      STM_SNAP_DEAD_LIST_MAX); new helper macro `STM_SNAP_HASH_LEN
      = 32`. `stm_snapshot_delete` extended with two out-params
      (`uint8_t **out_freed_cold_hashes`, `size_t
      *out_freed_cold_count`) — caller iterates the buffer in 32-
      byte strides calling `stm_cas_deref` per hash. New
      observability accessor `stm_snapshot_cold_dead_list_count`.
      Persistence: sp_encode_value / sp_decode_value handle the
      new tail; sp_validate_shadow gains a within-snap cold-hash
      uniqueness check (cross-snap collisions are legitimate per
      spec — distinct snap windows may each capture a drop of a
      same-hash cold extent, and snap A's cold-dead-list and
      snap B's cold-dead-list may both contain hash H without
      violating ColdSingleOwnership at the cold-extent-id level).
      Spec extension to dead_list.tla: parallel cold-tier model
      with `live_cold_extents`, `extent_hash`, `snap_cold_dead`,
      `cold_dereffed`, `used_cold_extents`. New actions
      `WriteCold(c, h)` + `OverwriteCold(c)`; SnapDelete extended
      to drain snap_cold_dead[s] into cold_dereffed. New
      invariants: `ColdExtentsTrackedSomewhere`,
      `LiveColdDisjointFromDead`, `LiveColdDisjointFromDereffed`,
      `DereffedColdDisjointFromDead`, `ColdSingleOwnership`. Two
      new buggy variants: `BuggyOverwriteColdForgetsDead`,
      `BuggyDeleteColdForgetsDeref` — both fire
      `ColdExtentsTrackedSomewhere`. dead_list.cfg green at 4.11M
      distinct states / depth 21 / 27s wall (cold-tier broadens
      the state space; previously a small bound). All 5 buggy
      demos fire. R54 audit: 0 P0 + 1 P1 + 0 P2 + 3 P3 — P1-1
      fixed inline (within-snap dedup-defense scan rejected
      legitimate intra-COW shared-hash drops; same fix at
      sp_validate_shadow); P3-1 + P3-2 + P3-3 forward-noted as
      P7-CAS-4 deferrals (dead-fallback, STM_ENOSPC at cap,
      arg-validation drift). test_fs grows 77 → 83 (5 new
      P7-CAS-4c tests + 1 R54 P1-1 regression: snap-holds-cold-
      after-overwrite, snap-delete-releases-cold-dead, no-snap-
      cold-overwrite-derefs-directly, cold-dead-list-persists-
      across-mount, snap-intra-cow-shared-hash-no-leak, arg
      validation). test_snapshot.c + test_sync.c +
      bench_snapshot.c updated for the new 6-arg
      `stm_snapshot_delete` signature. test_pool.c UB version
      assertion bumped 18 → 19. 35 ctest suites green default +
      ASan + TSan in isolation. Spec posture: 21 modules / 25
      fixed cfgs / 33 buggy cfgs (was 31; added 2 cold-tier
      buggy cfgs).
- [x] **P7-CAS-4b FastCDC sub-chunking** — substantive
      `ad6be38` + R53 close `b932714` +
      hash-fixup (this commit). Integrates `src/cdc/`
      (FastCDC, P7-prework, idle since 2026-04) into the cold-tier
      migration data plane. New per-stm_sync `stm_cdc cdc;` field
      initialized at sync_new from `stm_cdc_default_params` (ARCH
      §6.9.4: 8 MiB avg / 2 MiB min / 32 MiB max). New atomic
      1-drop+N-insert primitive `stm_extent_migrate_to_cold_chunked`
      alongside the existing single-chunk `stm_extent_migrate_to_cold`:
      pre-grows records[] capacity, in-place overwrites the src slot
      with chunks[0], appends chunks[1..K-1]. Pre-validates chunks tile
      [src_off, src_off+src_len) with no gap or overlap; refuses K=1
      (callers use the single-chunk API). New per-chunk descriptor
      `stm_extent_cold_chunk { off, len, content_hash[32] }`.
      `migrate_one_extent_locked` rewrite: read+decrypt → FastCDC
      chunk via `stm_cdc_chunk` → round boundaries to STM_UB_SIZE = 4
      KiB grid via new `round_chunk_boundaries` (round-to-nearest,
      drop collapsed boundaries, ensure last chunk >= STM_UB_SIZE) →
      per-chunk pre-flight via new `cas_chunk_intern_locked` helper
      (BLAKE3 + CAS lookup-or-insert with paddr reserve / AEAD-encrypt
      via `cas_chunk_encrypt_and_write_locked` / cas_insert on miss;
      cas_ref on hit) → atomic migrate (K=1 dispatches to old single
      API; K>=2 to chunked API) → drop-route src HOT replicas. Rollback
      walks completed chunks calling `stm_cas_deref` on each (CAS-miss
      inserts drop refcount → 0 → auto-GC at next commit; CAS-hit
      bumps undone). Default ARCH §6.9.4 params yield K=1 for 128 KiB
      recordsize-cap extents (FastCDC min=2 MiB > 128 KiB) → behavior
      identical to P7-CAS-2. Tests override CDC params via new
      test-only seam `<stratum/sync_testing.h>::stm_sync_set_cdc_
      params_for_test` (gated by `STRATUM_BUILD_TESTING_HOOKS`,
      mirrors snapshot_create_for_test pattern from R46 P2-1).
      cas.tla extended with `ChunkedMigrateToColdK2` action (atomic
      K=2 specialization; K=1 covered by existing MigrateToCold;
      K>=3 composes by induction). Closes pre-existing
      clamp/invariant inconsistency in MigrateToCold's CAS-hit
      branch (refcount clamps at MaxRef but invariant doesn't
      account; new precondition `EntryAt(h).refcount < MaxRef`
      mirrors C-impl's STM_OVERFLOW return on stm_cas_ref). cas.cfg
      green at 3.18M states / depth 10 / 3:32 (was 2.5M / depth 10 /
      40s — added action + cap precondition slightly broadens the
      state space). All 6 buggy demos still fire their respective
      invariants. test_fs grows 72 → 77 (5 new chunked-migrate
      tests: basic round-trip, intra-file dedup, persists across
      mount, full rehydrate clears CAS, cross-file dedup; plus a
      `mtc4b_read_full` per-extent helper since `stm_fs_read` is
      single-extent MVP). 35 ctest suites green default + ASan +
      TSan in isolation. No format break — STM_UB_VERSION = 18
      preserved. Spec posture 21/25/31 unchanged.
- [x] **P7-CAS-4a crossing-cold truncate** — substantive `a9e21f3` +
      R52 close `fe6ac61` + hash-fixup (this commit). Lifts the
      STM_ENOTSUPPORTED refusal P7-CAS-2 placed on truncating
      across a cold extent. Composes via cold-aware
      `stm_sync_read_extent_locked` (P7-CAS-2) + kept-prefix
      re-encrypt under fresh HOT AEAD nonce via
      `stm_sync_write_extent_locked` + the cold_overlap_cb
      pre-scan + post-deref bookend (P7-CAS-2) — extent_overwrite
      drops the cold record + post-deref calls stm_cas_deref on
      the captured hash. No new code paths; the comment block at
      the prior refusal site documents the composition. Three
      positive tests: basic, persists-across-mount, dedup-partial-
      release. cas.tla unchanged (the composition is captured by
      RehydrateOnWrite + extent.tla::Write). No format break.
- [x] **P7-CAS-3 closes R50 P2-1 + P2-3 + adds cold-extent reflink** —
      substantive `5e25cca` + R51 close `ee25ff6` + hash-fixup
      (this commit). Three-prong chunk:
      (1) **R50 P2-1 closure** (two-part). (1a) `cas_auto_gc_sweep_
      locked` moved from after extent/repair_log commits to BEFORE
      the per-device `stm_alloc_commit` loop in `stm_sync_commit`.
      The sweep's stm_alloc_free calls now produce PENDING
      (free_gen=target_gen) entries that alloc_commit PERSISTS in
      the on-disk alloc tree (alloc_commit's
      `free_gen<committed_gen` sweep predicate excludes them this
      cycle but the PENDING state survives).
      (1b) **R51 P1-1 inline fix**: `stm_alloc_load_tree_at` now
      rebuilds `pending_head` post-deserialize by walking the
      loaded tree for refcount=0 entries and emitting one
      `pending_entry` each with `free_gen=root_gen`. Without (1b),
      the unmount loses the in-RAM pending_head; the next mount's
      alloc_commit's sweep walks an EMPTY pending_head and never
      reclaims tree-resident PENDING entries — the cross-mount
      leak that the R50 P2-1 close claim depends on. With (1a) +
      (1b), the next sync_commit at target_gen+2 sweeps PENDING
      with free_gen<target_gen+2 → catches the entries → paddrs
      reach FREE. Crash recovery is now clean: alloc tree on disk
      has freed CAS paddrs as PENDING (not ALLOCATED), and the
      next mount + commit reclaims them.
      (2) **R50 P2-3 transactional sweep** — refactored
      `cas_auto_gc_sweep_locked` to a three-phase shape:
      Phase 1 captures `(hash, paddrs, n_paddrs)` tuples via
      `stm_cas_iter` + `cas_capture_zero_cb` (new tuple struct
      `cas_sweep_tuple`); Phase 2 alloc_frees per paddr with
      idempotent-tolerant pre-check (`stm_alloc_lookup` →
      refcount=0 → already PENDING from prior partial sweep + retry
      → skip; refcount>1 → STM_ECORRUPT — CAS chunks aren't
      reflink-shared); Phase 3 cas_gcs every captured hash with
      STM_EBUSY (P2-2 concurrent ref-bump case) + STM_ENOENT
      (concurrent gc) treated as skip. Phase 2 failure aborts
      WITHOUT calling cas_gc → cas_idx state unchanged → retry
      safe via the idempotent-skip path.
      (3) **Cold-extent reflink** — `reflink_collect_cb` now
      accepts COLD extents (was STM_ENOTSUPPORTED in P7-CAS-2 MVP).
      Phase 2 branches on `e->kind`: HOT calls `stm_alloc_ref` per
      replica + tracks via `hot_bumped`; COLD calls `stm_cas_ref`
      per cold record + tracks via `cold_bumped`. Phase 3 inserts
      via `stm_extent_reflink` (HOT) or `stm_extent_write_cold`
      (COLD) — the latter inheriting gen / key_id / origin from
      src so AEAD AD reconstructs identically across siblings.
      Rollback path symmetrically undoes both: walks the snapshot
      in order, undoes hot_bumped HOT paddrs (alloc_free) +
      cold_bumped COLD records (cas_deref); then drops dst-side
      records via `stm_extent_delete_file`.
      test_fs grows 67 → 69 — replaces `fs_reflink_refuses_cold_
      source` with three positive tests:
      `fs_reflink_cold_extent_basic_share` (CAS refcount=2 cross-
      file share), `fs_reflink_cold_extent_overwrite_diverges`
      (rehydrate on dst drops refcount to 1; src still reads cold),
      `fs_reflink_cold_extent_dst_must_be_empty` (STM_EEXIST pre-
      condition still enforced). cas.tla unchanged (cold-reflink
      composes via existing `BumpRef` / MigrateToCold's CAS-hit
      branch — no new spec action required). Spec posture
      21/25/31 preserved. 35 ctest suites green default + ASan +
      TSan in isolation. No format break — STM_UB_VERSION = 18.
- [x] **P7-CAS-2 migration / rehydrate / auto-GC data plane** —
      substantive `91fff73` + R50 close `6839cf0` + hash-fixup
      (this commit). Closes the second half of ARCH §6.9 / NOVEL #3 (the
      index foundation landed at P7-CAS). Adds the public API
      `stm_fs_migrate_to_cold(fs, dataset_id, ino)` that drives a
      per-extent pipeline: read+decrypt source HOT plaintext →
      BLAKE3-256 hash → CAS lookup-or-insert (allocator-fresh paddrs
      on miss + AEAD-encrypt under `stm_ad_cas` onto fresh replicas;
      `stm_cas_ref` bump on hit) → atomic hot→cold swap via new
      `stm_extent_migrate_to_cold` (preserves NoOverlapWithinIno
      across the transition by overwriting the matching slot in
      place) → drop-route source HOT replicas through the existing
      refcount-aware `sync_drop_paddr_locked`. Auto-rehydrate on
      writes: `stm_sync_write_extent_locked` pre-scans the (ds, ino)
      extent_idx for any COLD extent overlapping the write target,
      captures hashes, and after `stm_extent_overwrite` drops them
      `stm_cas_deref`s each captured hash — completing
      cas.tla::RehydrateOnWrite. Same pre-scan + post-deref bookend
      in `stm_sync_truncate`'s past-extent drop path. Crossing-COLD
      truncate + reflink-of-cold-source refused with
      STM_ENOTSUPPORTED in this MVP (deferred to P7-CAS-3 to avoid
      coupling the cold-aware read+slice into truncate's prefix-
      shrink and the CAS-bump shape into reflink's allocator-bump
      shape; these are clean future-chunk extensions). New
      COLD-aware read branch in `stm_sync_read_extent_locked`:
      resolves COLD extent → CAS entry → AEAD-decrypt under
      `stm_ad_cas` + pool metadata_key (cross-dataset shareable
      per ARCH §7.6.3, no per-dataset DEK on CAS chunks). Auto-GC
      sweep in `stm_sync_commit` (closes R49 P2-2 forward-note):
      walks the CAS index for refcount=0 entries via
      `stm_cas_iter`, calls `stm_cas_gc` per hash, routes returned
      paddrs through `stm_alloc_free`. Sweep runs BEFORE
      `stm_cas_index_commit` so the persisted btree reflects the
      post-GC state. Allocator-fresh paddrs in migration close
      R49 P2-1 forward-note (HotColdReplicasDisjoint enforced at
      the migration-layer caller via `stm_alloc_reserve` rather
      than inside `stm_cas_insert`). Migration is extent-
      granularity hashing for the MVP (one BLAKE3 hash per HOT
      extent → one CAS chunk; FastCDC sub-chunking is a P7-CAS-3+
      refinement). Snapshot-CAS interaction: snapshots that capture
      cold extents are NOT supported in this MVP (snap_idx doesn't
      track CAS hashes; auto-GC may reclaim chunks still referenced
      by a snapshot's view) — documented MVP limitation. test_fs
      grows 54 → 66 with 12 new integration tests (basic round-
      trip, dedup-two-files, distinct-content-two-entries,
      idempotency, persists-across-mount, rehydrate-on-write,
      dedup-then-rehydrate-one [refcount math], truncate-drops-
      cold, arg validation, RO refusal, reflink-cold refusal,
      truncate-crossing-cold refusal). cas.tla unchanged (P7-CAS-2
      is data-plane plumbing of the existing model); 21 modules /
      25 fixed cfgs / 31 buggy cfgs posture preserved. 35 ctest
      suites green default + ASan + TSan in isolation.
- [x] **P7-CAS cold-tier index foundation** — substantive `8eba90a`
      + R49 close `61205c7` + hash-fixup (this commit). Closes the
      first half of
      ARCH §6.9 / NOVEL #3 (the index + persistence + format
      break); migration / rehydration paths follow in P7-CAS-2.
      New `src/cas/cas_index.c` module realizes `cas.tla` against
      an in-RAM linear-array shadow + persistent btree_store-backed
      Bε-tree on device 0 (bp_kind STM_BPTR_KIND_CAS = 6, carved
      at v3 but unused until now). 64-byte value layout:
      n_replicas + paddrs[4] + refcount + length + gen. New AEAD
      AD struct `stm_ad_cas` (56 bytes) per ARCH §7.6.3.
      Format break STM_UB_VERSION 17 → 18: `ub_cas_index_root_gen`
      (le64) carved from head of `ub_reserved` (which shrinks
      784 → 776); `ub_cas_index_root` field at offset 288 was
      already there from v3. Extent record value layout adds a
      1-byte `kind` discriminator at offset 0 (0x01 = HOT, 0x02 =
      COLD) shifting n_replicas to byte 1 for HOT; COLD replaces
      bytes 8..39 with content_hash[32]. Bytes 40..95 unchanged.
      cas.tla: 6 actions / 9 invariants / 6 buggy demos — each
      fires its expected invariant. cas.cfg green at 2.5M states /
      depth 10 / 40s wall. 20 new test_cas_index unit tests + 2
      new test_fs integration tests (format-time presence + cross-
      mount persistence). 35 ctest suites green default + ASan +
      TSan in isolation. Spec posture 20/24/25 → 21/25/31.
- [x] **FastCDC pre-work** — landed at `5cb8900`; R27 close
      `a2ffd38` (0 P0 / 1 P1 / 4 P2 / 4 P3, all addressed
      except P2-4 / P3-2 / P3-4 deferred per audit close commit
      message). `src/cdc/cdc.{h,c}` + 12 tests on `tests/test_cdc.c`
      covering arg validation, determinism, shift-resistance (90%
      boundary match after 71-byte prepend), chunk-size
      distribution, forced-cutoff path, edge cases. Default + ASan
      + TSan all green.
- [x] **P7-1 spec scaffold: `extent.tla`** — landed at `4eace52`.
      Per-(ds, ino) extent layout: Write / Overwrite / Truncate /
      DeleteFile / AdvanceTxg actions; load-bearing invariant
      `NoOverlapWithinIno` plus LengthPositive / BirthTxgBound /
      AllExtentsInBounds / PaddrFreshness. Three buggy variants
      (`extent_overlap_buggy`, `extent_zero_length_buggy`,
      `extent_overwrite_forgets_drop_buggy`) all fire as designed.
      TLC: 1216 distinct states / depth 6 (MaxDatasets=1, MaxInos=2,
      MaxFileBlocks=2, MaxPaddrs=3, MaxTxg=1). Spec posture
      19/22/19 → 20/23/22.
- [x] **P7-2 extent C impl** — landed at `732b20e`; R34 close
      `433d2dd` (0 P0 / 0 P1 / 4 P2 / 4 P3 — P2-1 (out-arg
      zeroing on idx==NULL), P2-3 (iter cb pointer-retain doc),
      P3-1 (iter return-code doc) + P3-2 (advance_txg NULL test)
      fixed inline; P2-2 (concurrent-stress scope) + P2-4
      (cb-NULL-check pre-lock; already correct) + P3-3 (size_t
      overflow guard) + P3-4 (mutexattr return code) deferred per
      audit close commit message). New `src/extent/extent_index.c`
      module
      realizing extent.tla against an in-RAM map; the AEAD wrap
      helpers in `src/extent/extent.c` (Phase 4) coexist
      unchanged. Public API surface: `stm_extent_index_create /
      _close / _current_txg / _advance_txg`, `stm_extent_write /
      _overwrite / _truncate / _delete_file / _lookup_at / _iter
      / _count / _count_for_ino`. ERRORCHECK mutex with must_lock /
      must_unlock contract. `test_extent_index` 32 tests covering
      lifecycle + every spec action + every documented error
      path + concurrent stress. Default + ASan + TSan all green.
- [x] **P7-3 extent persistence** — landed at `b223975` (R35 audit
      clean: 0 P0 / 0 P1 / 0 P2 / 5 P3 deferred — bundled into
      substantive). STM_UB_VERSION 11 → 12. New UB
      fields `ub_extent_root` (64-byte stm_bptr at offset 3128) +
      `ub_extent_root_gen` (le64 at offset 3192) carved from the
      head of `ub_reserved`. New `STM_BPTR_KIND_EXTENT_TREE = 10`.
      Single unified Bε-tree under `ub_extent_root` keyed by
      `(le64 ds || le64 ino || le64 off)`, valued by 32-byte
      ARCH §11.6.1 record. Same envelope as ub_main_root /
      ub_snap_root: btree_store-encoded, AEAD-encrypted with
      nonce `paddr || gen || pool_uuid` + AD `pool_uuid ||
      device_uuid_0`. Idempotent commit via internal dirty flag;
      atomic shadow-swap on load_at; structural validator
      enforcing NoOverlapWithinIno + paddr-disjointness on the
      loaded shadow. MVP cap: 24-bit length (≤ 16 MiB - 1, far
      above any realistic recordsize). xxh = 0 (AEAD tag is
      integrity); compression = 0 (no compression in MVP).
      Sync.c wire-in: `stm_extent_index *extent_idx` field +
      mirror fields, `compute_merkle_root` extended to fold
      extent_csum, `build_uberblock` extended with extent_root
      params, hydration on `sync_open` from ub_extent_root,
      commit on `sync_commit`, close on `sync_close`. New
      accessor `stm_sync_extent_index`. v11 pools refused at v12
      mount via uniform STM_EBADVERSION (existing handler).
- [x] **P7-4 fs.c/sync.c COW path integration** — landed at `bb2d666`;
      R36 close `64a6278` (1 P0 + 3 P1 + 3 P2 + 3 P3 — P0-1
      (use-after-free via fs->lock release/reacquire) + P1-1
      (paddr leak in drop loop) + P1-2 (wedge-guard race; same
      root cause as P0-1) + P1-3 (AEAD mode autodetect drift) +
      P2-1 (drop-loop comment-vs-impl drift) + P3-1 (advance_txg
      STM_EINVAL-impossibility doc gap) all fixed inline; P2-2
      (read-path bounds asymmetry) + P2-3 (hole-spans-len vs
      hole-up-to-next-extent) + P3-2 (write/read len==0 asymmetry)
      + P3-3 (snap-deleted-then-cow + multi-snap test scenarios)
      deferred per audit close commit message). New
      `stm_sync_write_extent` / `stm_sync_read_extent` in sync.c
      compose alloc.reserve + AEAD encrypt + bdev.write +
      extent_overwrite + drop-routing. New helper
      `sync_drop_paddr_locked` realizes the C-impl boundary between
      extent.tla::Overwrite, dead_list.tla::OverwriteBlock, and
      allocator.tla::Free: each dropped paddr feeds through
      `stm_snapshot_index_overwrite_block` (routes to most-recent-
      snap's dead-list if any) or `stm_alloc_free` direct (no
      snapshot). New `stm_fs_write` / `stm_fs_read` in fs.c are
      thin wrappers with FS_GUARD_WRITE / FS_GUARD_READ. New
      `stm_fs_sync_for_test` accessor in fs_testing.h lets tests
      drive the snapshot/dataset/extent indices directly.
      `stm_extent_index_advance_txg(s->current_gen)` called per
      sync_create / sync_open / sync_commit (R35 forward-looking
      note acted on). MVP constraints: len > 0, multiple of
      STM_UB_SIZE, ≤ 128 KiB; off multiple of STM_UB_SIZE; single-
      extent per call; encryption with pool-wide metadata_key
      (per-dataset DEKs deferred). test_fs grows 9 → 17 (8 new
      P7-4 tests covering roundtrip / hole / args / COW with-snap
      asserting dead_list_count 0→1 / COW without-snap / cross-
      mount durability / RO blocks / multi-extent).
- [x] **P7-7 send/recv MVP** — landed at `a42d84d`;
      R39 close `73e9f20` (0 P0 / 0 P1 / 3 P2 / 3 P3 — P2-1 send
      replica fallback + P2-2 strict n_replicas + P2-3 recv
      record-size cap + P3-3 dead-code cleanup all fixed inline;
      P3-1 stale-paddr-on-busy-source + P3-2 recv-durability
      documented as known caveats in send_recv.h). New `src/send_recv/` module with
      separate send + recv translation units sharing a unified
      `<stratum/send_recv.h>` surface. Wire format: 16-byte framing
      header (type/flags/body_len) per record; HEADER once
      (52B body — magic STMS / version 1 / src_pool_uuid / dataset_id
      / from_snap_id / to_snap_id / reserved); EXTENT* (32B meta —
      ino/off/len/gen — followed by `len` plaintext bytes); END (32B
      body = BLAKE3 csum over every prior record's framing+body).
      Send: snapshots the matching extent set at init time, then
      `stm_send_next` emits records one-at-a-time into a caller-
      sized buffer; STM_ERANGE on too-small with `*out_len_needed`.
      Each EXTENT decrypts the source's ciphertext via
      `stm_extent_decrypt` and ships plaintext (caller wraps for
      transport). Recv: strict state-machine HEADER → BODY → DONE
      with sticky FAILED on errors; `stm_recv_apply` parses framing,
      validates, hashes, dispatches EXTENT bodies via
      `stm_sync_write_extent` (which re-encrypts under the target
      pool's `metadata_key` with fresh paddrs — no cross-pool nonce
      hazard). End-of-stream csum verified before DONE; mismatch →
      STM_EBADTAG. `stm_extent_iter_ds(idx, ds, cb, ctx)` added to
      iterate every live extent of a dataset across all inos in
      (ino, off) order. `stm_sync_metadata_key` accessor added so
      the send module can reach the source key without duplicating
      sync.c's encrypt logic. test_send_recv = 10 tests (init args
      validation, full-send roundtrip across 3 extents on 2 inos,
      bad magic refused, extent-before-header refused, tampered
      end-of-stream csum refused, finish-before-end → STM_EPROTOCOL,
      buffer-too-small → STM_ERANGE retry path). MVP gap:
      incremental send (from_snap_id != 0) is API-wired but the
      gen filter is best-effort because `snapshot.created_txg` and
      `sync.current_gen` are independent counters — closed in P7-8.
      No format break in P7-7; STM_UB_VERSION stays at 13.
- [x] **P7-16 reflinks** — landed at `76ce44f`; R48 close
      `1951f65`. Closes ARCH §11.12 (FICLONE-shape reflinks) at
      v1 MVP scope: same-dataset whole-file reflinks. New public
      API `stm_fs_reflink(fs, src_ds, src_ino, dst_ds, dst_ino)`
      bundles a 3-phase composition under sync->lock: collect src
      extents via `stm_extent_iter_ds`, bump `stm_alloc_ref` on every
      replica paddr, insert reflinked records via
      `stm_extent_reflink` with origin INHERITED from src. Format
      break STM_UB_VERSION 16 → 17: extent on-disk value 64 → 96
      bytes adding `origin_dataset_id` (offset 64) +
      `origin_ino` (72) + `origin_off` (80) + 8 reserved bytes
      (88..95). The origin triple names the (ds, ino, off) at which
      the AEAD ciphertext was first encrypted; both reflink-siblings
      reconstruct AD from origin (rather than live ds/ino/off) so
      AEGIS-256 verify succeeds across the share. Spec replaces
      `LiveReplicasDisjoint` with `SharedReplicasAreCohabit`:
      paddr-share legitimate ONLY when whole replica set + gen +
      key_id + origin tuple matches (catches partial overlap +
      whole-share-with-mismatched-tuple). New extent.tla::Reflink
      action + `BuggyReflinkRotatesOrigin` variant + cfg
      (`reflink_rotates_origin_buggy.cfg`) fires at depth 4 / 595
      states. New `OriginConsistentInBounds` invariant
      (origin_off + len ≤ MaxFileBlocks). New `DisableReflink` cfg
      toggle keeps the bumped extent.cfg bounds (838,164 states /
      ~1m wall) tractable; extent_keyids.cfg now exercises Reflink
      at smaller bounds with MaxDatasets=2 (~3.6M states / ~4m
      wall). All 5 prior buggy cfgs updated with DisableReflink=
      TRUE and still fire as designed. C-impl AD reconstruction at
      read / scrub / send paths sources from `rec.origin_*` instead
      of live identity; send_extent_meta gains origin fields so the
      per-extent send wire (post-snapshot capture) reconstructs the
      same AD as the live read path. ex_validate_shadow's
      cross-record disjointness replaced with cohabit
      classification. Cross-dataset reflinks deferred per ARCH
      §11.12.3 same-key requirement; refused with new STM_EXDEV
      error code (-18). 7 new test_extent_index unit tests + 9 new
      test_fs integration tests + 2 R48 regression tests
      (incremental_send_includes_reflink_in_window for P0-1,
      fs_reflink_snap_dual_overwrite_no_wedge for P1-1);
      test_extent_index 62 → 69; test_fs 42 → 52; test_send_recv
      +1. R48 fold: P0-1 added `link_gen` field at v17 offset 88
      (separate from AEAD `gen`; send filter uses link_gen so
      reflinks in (S_from, S_to] are emitted); P1-1 refcount-aware
      `sync_drop_paddr_locked` (DecRef-only when refcount > 1, no
      dead-list capture); P2-1 Phase 3 rollback rewrite (no leak
      on delete_file failure); P2-2 origin_off+dlen overflow check
      at decode. STM_UB_VERSION stays 17 (link_gen folds into the
      v17 reserved bytes). 34 ctest suites green default + ASan
      + TSan in isolated runs.
- [x] **P7-15 repair-log persistence** — landed at `c02cba8`;
      R47 close `82fe30e` (0 P0 + 0 P1 + 1 P2 + 5 P3). Closes
      the long-deferred R38 P3-1 (since P7-6) for the on-disk
      audit-trail surface ARCH §7.15.4 / bptr.tla::LogIntegrity
      committed to. Every scrub-driven replica rewrite now emits
      a `stm_repair_log_entry` into a per-pool single-leaf btnode
      tree rooted at `ub_repair_log_root`; entries carry timestamp
      (CLOCK_REALTIME), target/source paddrs, replica indices,
      corruption type (CSUM_FAIL / IO_ERR — sourced from a Phase-1
      `replica_io_err[]` flag added in this chunk), and
      verification result (OK_VERIFIED / FAIL — emit fires on both
      success and failure paths). New module `src/repair_log/`
      modeled on stm_keyschema (plaintext + Merkle-covered,
      append-only, idempotent commit per R14b P2-1, in-RAM linked
      list with O(1) tail-append). Format break STM_UB_VERSION
      15 → 16: three new fields carved from `ub_reserved` head —
      `ub_repair_log_root` (stm_bptr at 3200), `ub_repair_log_root_
      gen` (le64 at 3264), `ub_repair_log_next_seq` (le64 at 3272);
      `ub_reserved` shrinks 864 → 784. New bptr kind
      `STM_BPTR_KIND_REPAIR_LOG = 11`. R47 P2-1 folded
      `repair_log_csum` into `compute_merkle_root` as the 7th
      input — closes the asymmetry where keyschema (also plaintext
      + Merkle-covered) was Merkle-bound but repair_log was not,
      so an offline tamper of the audit trail now fires a Merkle
      mismatch at mount. R47 P3-1 moved the single-leaf MVP cap
      enforcement from `_commit` (where exceeded → wedged
      sync_commit, halted all pool progress) to `_emit` (refuses
      STM_ERANGE; scrub cb absorbs silently — repair lands, only
      audit entry dropped). R47 P3-2: tampered paddr-device check
      surfaces STM_ECORRUPT instead of STM_EINVAL. R47 P3-3 + P3-4
      docstring fixes on `_iter` (cb-side state is the only
      early-termination signal; cb runs lock-held and MUST NOT
      re-enter the API). 7 new test_repair_log tests + 1 new
      test_fs integration test. test_crash_inject CMake timeout
      bumped 180s → 300s (TSan headroom under the new per-cycle
      mutex acquisitions). 34 ctest suites green default + ASan +
      TSan in isolated runs.
- [x] **P7-14 snap chain-ordering regression test** — landed at
      `01b5233`; R46 close `485f0ef` (0 P0 + 0 P1 + 1 P2 + 4 P3).
      Closes the long-deferred R40 P3-3 (no on-disk regression
      test for `sp_validate_shadow`'s `ChainExtentTxgOrdered`
      check; introduced in P7-8). The R40 P2-1 fix added an
      in-process producer-side check at `stm_snapshot_create`
      that refuses STM_EINVAL on chain inversion; the on-disk
      validator at `sp_validate_shadow` is the second line of
      defense for cases where a buggy producer or tampered disk
      sneaks past it, and now has matching regression coverage.
      New test-only API `stm_snapshot_create_for_test` (in
      `<stratum/snapshot_testing.h>`) bypasses ONLY the R40 P2-1
      check; all other arg validation runs. Three new tests: in-
      process check fires on same-dataset chain inversion +
      tolerates per-dataset isolation + accepts the equality case
      (`snap_create_in_process_chain_ordering_refused`); _for_test
      seam accepts the inverted shape and still validates every
      other prelude check
      (`snap_create_for_test_bypasses_chain_ordering_check`); on-
      disk validator rejects the chain-inverted shape at mount-
      load with STM_ECORRUPT
      (`fs_snap_chain_inversion_on_disk_refused_at_mount`).
      Refactored `stm_snapshot_create`'s body into a static
      `snapshot_create_inner` helper that takes a
      `skip_chain_check` flag; both public functions collapse to
      one-line forwards. R46 P2-1: gated `_for_test` symbol
      behind a new `STRATUM_BUILD_TESTING_HOOKS` CMake option
      (default ON for in-tree dev/test build, opt-out via
      `-DSTRATUM_BUILD_TESTING_HOOKS=OFF`); verified out-of-tree
      that the production-built `libstm_snapshot.a` exports only
      `_stm_snapshot_create` with the option OFF. R46 fixes: P2-1
      + P3-1 (tightened on-disk assertion to STM_ECORRUPT) + P3-2
      (consolidated arg-validation prelude into the inner helper)
      + P3-3 (added NULL-name, NULL-out_id, oversize-name to
      _for_test arg test) + P3-4 (added chain-inversion rejection
      to reference/13-snapshot.md validator prose). No format
      break, no spec change. test_snapshot 41 → 43; test_fs 40 →
      41; 33 ctest suites green default + ASan + TSan in isolated
      runs.
- [x] **P7-13 fs_create_dataset** — landed at `e6a751c`; R45 close
      `f30db5e` (0 P0 + 0 P1 + 1 P2 + 4 P3). New public API
      `stm_fs_create_dataset(fs, parent_id, name, *out_id)` bundles
      `stm_dataset_create_child` + `stm_sync_add_dataset_key` under
      `fs->lock` so the FS observer never sees a half-created
      dataset. The freshly-created id is immediately usable for
      `stm_fs_write` / `stm_fs_read` — removes the long-standing
      test_fs restriction "only ds=1 (root) writes work without
      explicit DEK install". Atomicity: on
      `stm_sync_add_dataset_key` failure the freshly-created leaf
      is rolled back via `stm_dataset_destroy` (infallible-by-spec
      for a non-root no-children leaf under fs->lock; the project
      idiom skips runtime assert and uses a `(void)` cast with the
      analysis pinned in a comment). R45 P2-1 hardened the
      wrap-key source: substantive `e6a751c` accepted a per-call
      `stm_fs_create_dataset_opts` (keyfile_path XOR janus_socket)
      that let a caller persist a wrap-key-mismatched CURRENT
      entry, which R42 P1-1's hard-fail-on-CURRENT-unwrap-failure
      would turn into a permanent mount refusal on the next
      mount. ARCH §7.7 defines wrap keys as pool-wide so per-call
      overrides have no documented use case — the R-close pass
      removed the opts struct and now the fs handle retains
      `keyfile_path` / `janus_socket` strdup'd at mount, with the
      create call loading from that source per-call. Mismatch is
      impossible by construction. R45 fixes: P2-1 + P3-1 (docstring
      drift on return codes — switched to "errors propagate from
      {keyfile_load, janus_client_connect, dataset_create_child,
      sync_add_dataset_key}") + P3-2 (defensive wedge-on-rollback-
      failure was dead code, replaced with `(void)` cast +
      analysis comment) + P3-4 (added
      `fs_create_dataset_name_length_boundaries` for empty / over-
      max / exactly-NAME_MAX, plus `fs_create_dataset_multi_call_
      sequencing` for 5 datasets in a single mount with distinct
      ids + remount roundtrip). P3-3 (next_id burn on STM_ERANGE
      rollback path: cap is 268M, cosmetic at any realistic scale)
      deferred. No format break, no spec change. test_fs 31 → 40;
      33 ctest suites green default + ASan + TSan in isolated runs.
- [x] **P7-12 truncate fault-free Phase 3** — landed at `5eba5de`;
      R44 close `bb5e088` (0 P0 + 0 P1 + 0 P2 + 4 P3 — green
      signal; P3-1 SPEC-TO-CODE refinement-row backfill + P3-2
      misleading Phase 3 error-comment rewrite + P3-4 peek
      zero-before-validate convention all fixed inline; P3-3
      end-to-end ENOMEM-injection regression test continues R43
      P3-2's deferral pending a malloc-failure harness in v2's
      test infra). Closes the last documented atomicity gap:
      R41 P3-1 case (b) (Phase 3 ENOMEM after Phase 2 succeeded
      → partial in-RAM state committable by next sync_commit).
      Adds two new extent_idx APIs:
        - `stm_extent_truncate_peek(idx, ds, ino, new_size,
            *out_n_extents, *out_n_replicas_total)` — pure-read,
            counts past-extents + their total replica paddrs without
            mutating the index.
        - `stm_extent_truncate_into(idx, ds, ino, new_size,
            drop_idx_buf, drop_idx_cap, paddrs_buf, paddrs_cap,
            *out_n_dropped)` — truncate using caller-provided
            pre-allocated buffers. Never allocates internally.
            Returns STM_ERANGE atomically (no index mutation) if
            either cap is insufficient.
      stm_sync_truncate's new flow: lock + wedged/RO check → Phase 1
      lookup crossing → Phase 1b peek + pre-allocate drop_idx +
      paddrs → Phase 2 read+re-encrypt crossing prefix → Phase 3
      `_into` (fault-free) → drop-route past-extent paddrs → unlock.
      Pre-allocation runs BEFORE Phase 2's extent_overwrite, so any
      ENOMEM surfaces with the index unchanged. Peek's count remains
      consistent at Phase 3 time because Phase 2 only mutates the
      crossing extent's range (off in [crossing.off, crossing.off +
      crossing.len) ⊂ [0, new_size)); past-extents at off ≥ new_size
      are untouched. Composition with P7-11's single-lock-span makes
      the whole truncate atomic w.r.t. concurrent commit / write AND
      ENOMEM-safe. No format break, no spec change. test_extent_index
      51 → 55 (4 new tests for the peek + into APIs); 33 ctest suites
      green default + ASan + TSan in isolated runs.
- [x] **P7-11 truncate _locked atomicity refactor** — landed at
      `0a59ab2`; R43 close `9af916e` (0 P0 + 0 P1 + 0 P2 + 4 P3 —
      P3-1 docstring honesty pass + P3-3 scrub-cascade note fixed
      inline; P3-2 regression test deferred until case-(b) fix
      lands; P3-4 pre-existing pool.rdlock omission out of scope).
      Refactors stm_sync_write_extent / stm_sync_read_extent into
      public-wrapper + internal `_locked` variants, then rewrites
      stm_sync_truncate to hold sync->lock across all three phases
      under one acquisition. Closes **R41 P3-1 case (a)** (concurrent
      stm_sync_commit between Phase 2 and Phase 3 splits the on-disk
      view) and **R41 P3-2** (same gap, scrub-flavored). The R41
      P3-1 **case (b)** (Phase 3 stm_extent_truncate ENOMEM after
      Phase 2 succeeded → partial in-RAM state committable by next
      sync_commit) is NOT closed by this chunk; the on-disk state
      remains a POSIX-atomicity gap (no invariant violated; no
      corruption hazard). Operator mitigation is to retry the
      truncate (idempotent: second call's Phase 1 finds no crossing
      extent and Phase 3 retries the drop). Closing case (b)
      requires Phase 3 pre-allocation OR a true Phase 2 rollback
      primitive on the extent_idx; deferred follow-on. Lock-graph
      unchanged (sync.lock OUTER → extent_idx.lock + per-device
      alloc.lock INNER; no back-edges). Lock-hold trade-off: the
      crossing extent's decrypt + encrypt + bdev I/O all under
      sync->lock; cascades scrub-step latency by the same window
      via the verify cb's brief s->lock takes (no deadlock). No
      format break, no spec change. 33 ctest suites green default
      + ASan + TSan in isolated runs.
- [x] **P7-10 per-dataset DEKs** — landed at `a3610f2`;
      R42 close `394150a` (0 P0 + 1 P1 + 2 P2 + 5 P3 — P1-1
      mount-fail on tampered CURRENT for any dataset_id (was only
      pool (0,0) pre-fix, exposing a runtime DoS surface specific
      to P7-10's load-bearing per-dataset CURRENTs); P2-1a send
      now snapshots a (key_id → DEK) map at stm_send_init so
      concurrent rotate+overwrite+sweep can't poison emit;
      P2-1b scrub cb classifies missing-DEK as OK (race
      tolerance, not corruption); P2-1c misleading send.c comment
      rewritten; P2-2 wedged/RO guards on sweep + add_dataset_key
      + rotate_dataset_key (sweep mutates the DEK map; symmetric
      guards added to add/rotate); P3-1 extent.tla gains
      NonceUniquenessIndependentOfKey doc-shaped invariant
      recording the allocator-freshness composition; P3-3 super.h
      v15 docstring rewritten to accurately describe the
      uberblock-version check (NOT extent-value-layer) defense
      + tamper-then-mount runtime DoS posture; P3-4
      sync_resolve_current_dek_locked docstring documents the
      write-side-only contract + caller wedged/RO obligation.
      P3-2 (docs-with-substantive-commit) deferred per
      project's three-commit pattern; P3-5 (extent_full.cfg
      bumped MaxKeyIds × bumped MaxFileBlocks × bumped MaxPaddrs)
      deferred as tractability trade-off / nightly CI candidate).
      Wires the keyschema layer's per-dataset DEKs
      (P4-4c) into the extent write/read paths. Every extent now
      carries a `key_id` field naming which DEK in the dataset's
      keyschema decrypts it; sync resolves DEK via
      `(dataset_id, key_id)` instead of using `metadata_key`.
      `stm_sync_create` auto-installs the root dataset's DEK at
      format time as keyschema entry `(1, 0, CURRENT)` alongside
      the pool metadata key `(0, 0)`. The production scrub β cb
      (P7-5) and send/recv (P7-7) pick the DEK by the extent's
      stamped `key_id` — RETIRED keys remain reachable so
      pre-rotation extents stay decryptable; the receiver
      re-encrypts under its own pool's CURRENT DEK for the target
      dataset. `stm_sync_keyschema_sweep` walks the extent index
      and refuses to prune any RETIRED key with live extent
      references (closes the long-standing P4-4c TODO; maps to
      key_schema.tla::PruneSafety). Format break STM_UB_VERSION
      14 → 15: extent on-disk value's offset-56 slot — the
      always-zero `xxh` field in v13/v14 — is repurposed for
      `key_id` (le64); EX_VAL_LEN stays 64. v14 pools fail at the
      uberblock version check. Spec extension:
      `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`;
      Write/Overwrite/Truncate stamp it. `extent.cfg` holds
      `MaxKeyIds=1` to preserve the P7-9 partial-shrink coverage
      at 838164 distinct states; new `extent_keyids.cfg` runs
      MaxKeyIds=2 at the pre-P7-9 bound (67304 distinct states;
      5s wall) so spanning-rotation scenarios — distinct extents
      coexisting under distinct key_ids — are realized in TLC.
      All 4 buggy extent cfgs still violate as expected.
      C surface: new private helper `sync_resolve_current_dek_locked`
      (looks up `keyschema_lookup_current` + `sync_dek_find` under
      s->lock); `stm_extent_write` / `_overwrite` signatures gain
      `uint64_t key_id`; in-RAM `stm_extent_record` gains `key_id`;
      `ex_encode_value` / `ex_decode_value` round-trip key_id
      through the on-disk envelope. The scrub β cb takes s->lock
      briefly to look up the DEK by `(rec.dataset_id, rec.key_id)`
      — lock-order `sc.lock → pool.rdlock → s.lock` is symmetric
      with `stm_sync_set_scrub_durable_bytes`. Plaintext hygiene:
      every fresh DEK is copied to a stack-local 32-byte buffer
      and `stm_ct_memzero`'d on every exit path of write/read/scrub/
      send. Tests: test_keyschema_rotate 15 → 17 (root DEK auto-
      installed at create, root DEK persists across mount); test_fs
      26 → 30 (per-dataset DEK rotation roundtrip with kept-decryption
      under RETIRED keys, sweep refuses prune with extent refs,
      sweep succeeds after overwrite drops ref, unprovisioned ds
      refused with STM_ENOENT); test_extent_index persist roundtrip
      extended with distinct key_ids verifying field round-trip;
      test_pool STM_UB_VERSION assertion bumped 14 → 15. Mechanical:
      tests using non-root dataset ids now use ds=1 (root) since
      the fs layer doesn't yet expose a `fs_create_dataset` that
      bundles dataset_index + keyschema provisioning — that
      integration is a future chunk. 33 ctest suites green default
      + ASan + TSan in isolated runs.
- [x] **P7-9 truncate partial-extent split** — landed at
      `ad95a5d`; R41 close `5530a0e` (0 P0 + 0 P1 + 0 P2 + 5 P3
      — P3-3 strict dead-list count assertion + P3-4 TLC bound
      bump (MaxFileBlocks 2 → 3 + MaxPaddrs 4 → 5 to expose
      branch-(b) unique states; 11594 → 838164 distinct) + P3-5
      rec.len defense check fixed inline; P3-1/P3-2 atomicity
      gaps documented as known limitations in stm_sync_truncate's
      docstring, deferred to a future `_locked` refactor of
      write_extent / read_extent). Closes the long-standing MVP
      gap where `stm_extent_truncate` dropped only fully-past-
      truncation extents — any crossing extent (off < new_size <
      off+len) was left at its original full length, leaving
      bytes past new_size readable until a future overwrite. New
      public `stm_sync_truncate(s, ds, ino, new_size)` composes:
      Phase 1 (`stm_extent_lookup_at` at off=new_size-1 to find
      the crossing extent — NoOverlapWithinIno guarantees ≤ 1);
      Phase 2 if crossing exists, malloc plaintext buffer,
      `stm_sync_read_extent` to read+decrypt the full extent,
      then `stm_sync_write_extent` to re-encrypt the kept
      `[0, prefix_len)` bytes — the latter's `extent_overwrite`
      drops the original via the COW path with replicas routed
      through dead-list / free; Phase 3 acquires sync.lock for
      atomicity of `stm_extent_truncate` (drops every extent past
      new_size) + per-paddr `sync_drop_paddr_locked` routing.
      Plaintext buffer is `stm_ct_memzero`'d on every exit path.
      Spec refinement in `extent.tla::Truncate`: a second branch
      replaces the single crossing extent under FRESH replicas
      (`new_replicas \cap used_paddrs = {}`) at gen = current_txg
      — re-encrypting under fresh paddrs prevents `(paddr, gen)`
      reuse that would otherwise share a nonce between the
      original full ciphertext and the new shrunk prefix's
      plaintext. test_fs 20 → 26 (6 new tests):
      fs_truncate_inside_extent_shrinks_prefix (8K → 4K with
      byte-exact roundtrip + hole verify),
      fs_truncate_at_extent_boundary_is_noop_for_extent (4K
      truncate at 4K leaves extent intact),
      fs_truncate_to_zero_drops_all_extents (3 extents → 0),
      fs_truncate_past_eof_is_noop (4K → 16K),
      fs_truncate_with_snapshot_routes_old_paddrs_to_dead_list
      (snap + 8K → 4K asserts strict count == 1 per R41 P3-3),
      fs_truncate_args_validated (NULL / 0 ds-ino / unaligned
      new_size). MVP constraints: new_size must be 4 KiB-aligned;
      atomicity across crash / partial failure is the caller's
      responsibility (POSIX truncate-vs-concurrent-write and
      truncate-vs-commit are not serialized at the sync layer).
      No format break.
- [x] **P7-8 snap-gen alignment** — landed at `4f40743`;
      R40 close `c9c29ee` (0 P0 / 0 P1 / 1 P2 / 6 P3 — P2-1
      concurrent-create chain inversion + P3-1 send_recv.h docstring
      drift + P3-2 extent_txg roundtrip assertion + P3-4 swapped
      from/to test + P3-5 equal extent_txg test + P3-7 misleading
      v13 decoder rejection comment all fixed inline; P3-3 byte-
      level structural validator regression test + P3-6 absolute
      bound check on extent_txg deferred per audit close commit
      message). Closes the P7-7 incremental-send gap. New 8-byte
      `extent_txg` field on every `stm_snapshot_entry`, captured
      from `sync.current_gen` at SnapshotCreate. Send filters by
      `extent_txg` (same counter space as `extent.gen`) instead
      of `created_txg` (snap-index counter, distinct space) —
      filter is now authoritative when callers follow the
      documented bracketed pattern `commit → snap_create → commit`.
      Format break v13 → v14: snapshot record value layout
      `SP_VAL_FIXED` 44 → 52 with the new field at offset 24..32;
      v13 entries length-rejected at v14 mount via uniform
      STM_EBADVERSION (uberblock.c version gate). Spec change:
      `snapshot.tla` extended with new variable `sync_gen`
      (distinct from `current_txg`); `Write` bumps `sync_gen`
      only; `SnapshotCreate` captures `sync_gen` as
      `snap_extent_txg` (and bumps `current_txg` only); new
      invariants `ExtentTxgBoundedBySync` + `ChainExtentTxgOrdered`;
      new buggy variant `BuggyExtentTxgUnbounded` + companion
      config `snapshot_extent_txg_unbounded_buggy.cfg` (TLC fires
      `ExtentTxgBoundedBySync` at state 2). Spec posture
      20/23/23 → 20/23/24. C surface: `stm_snapshot_create`
      signature gains `uint64_t extent_txg` arg; impl validates
      `extent_txg ≥ prev_snap.extent_txg` under idx->lock at
      create time (R40 P2-1 race fix); structural validator
      `sp_validate_shadow` extended with chain-edge ordering check;
      new accessor `stm_sync_current_gen`. test_send_recv 10 → 13
      (3 new tests: incremental_send_filters_by_extent_txg with
      bracketed-commit pattern, incremental_send_rejects_swapped_
      from_to, incremental_send_equal_extent_txg_chain_accepted_
      send_rejected). test_snapshot extent_txg roundtrip
      assertion added to existing persist-roundtrip test.
      Mechanical: every `stm_snapshot_create` call site updated
      (test_snapshot, test_sync, test_fs, bench) — 0 for unit/
      bench, `stm_sync_current_gen(s)` for sync-aware paths.
      ROADMAP §10.2 "send + receive roundtrip preserves data +
      metadata + snapshots" exit criterion now achievable for
      snap-bounded streams. Operational requirement (documented
      in send_recv.h): callers must `stm_sync_commit` after every
      `stm_snapshot_create` to establish the strict gen boundary
      that makes the filter exact.
- [x] **P7-6 replica-list extension** — landed at `2eb898d`;
      R38 close `8d0c172` (0 P0 / 0 P1 / 0 P2 / 2 P3 — P3-1 cb
      LogIntegrity-deferral docstring + P3-2 test_pool.c version-
      history comment freshness, both fixed inline). Format break
      v12 → v13: extent
      record value layout grows 32B → 64B with up to 4 replica
      paddr slots per ARCH §11.6.1. extent.tla extended with
      `replicas` field, `MaxReplicasPerExtent` constant, and
      `LiveReplicasDisjoint` + `ReplicasNonEmpty` +
      `ReplicaCountBounded` invariants; new buggy demo
      `extent_replica_collision_buggy.cfg`. C impl: `stm_extent_record`
      grows; `stm_extent_write` / `_overwrite` API takes
      `(paddrs, n_paddrs)`; `stm_extent_lookup_by_paddr` scans full
      replica set; encode/decode validates within-set distinctness
      + sentinel-zero unused slots. Sync layer: `stm_sync_write_extent`
      reserves N=mirror_n replicas across N distinct devices,
      encrypts ONCE under (replicas[0], gen) and writes bytewise-
      identical ciphertext+tag to each replica's paddr;
      `stm_sync_read_extent` walks replicas (first AEAD-OK wins);
      `sync_scrub_verify_cb` realizes bptr.tla's full ScanRead ×
      RewriteReplica machine — picks first OK source, rewrites
      non-OK replicas, verify-back-reads each, classifies
      OK / REPAIRED / UNREPAIRABLE per
      bptr.tla::ResultClassification. test_extent_index 42 → 51
      (9 P7-6 multi-replica tests); test_scrub 30 → 34 (4 P7-6
      replica-walk tests including end-to-end repair). Spec posture
      20 / 23 / 23.
- [x] **P7-5 production scrub cb** — landed at `38e6799`;
      R37 close `fc5f619` (0 P0 / 0 P1 / 3 P2 / 3 P3 — P2-1 (cb
      transient-error overload) + P2-2 (cb concurrency caveat
      missing from public docstring) addressed via doc + caveat;
      P2-3 (verify test `>=` assertions) tightened to strict
      equality via alloc-tree walk; P3-1 (rec.len overflow guard)
      preempted in substantive; P3-2 (pool_device_bdev forward-
      compat note) added inline; P3-3 (docstring brittleness on
      stacked extents) acknowledged). New `stm_extent_lookup_by_paddr`
      (extent.h + extent_index.c) — exact-paddr live-extent lookup,
      O(n) scan, first match wins by live-paddr `PaddrFreshness`.
      New `stm_sync_scrub_install_production_cb` (sync.h + sync.c)
      wires a static `sync_scrub_verify_cb` onto a scrub handle:
      lookup_by_paddr → if hit, `stm_pool_device_bdev` (rdlock-
      snapshot) + `stm_bdev_read` of `rec.len + tag_len` bytes +
      `stm_extent_decrypt` with the same nonce/AD as the write
      path; OK → `STM_SCRUB_VERIFY_OK`; AEAD-tag failure or bdev
      I/O error → `STM_SCRUB_VERIFY_UNREPAIRABLE`. Mid-extent
      blocks + metadata/bootstrap blocks return OK trivially. Lock
      hierarchy: cb runs under `sc.lock + pool.rdlock` (existing
      scrub contract); takes `extent_idx.lock` briefly inside
      lookup; does NOT take `sync.lock` (extent_idx, pool,
      pool_uuid, metadata_key all immutable post-create or
      independently locked). Plaintext hygiene via
      `stm_ct_memzero` before free. test_fs grows 17 → 20 (3 new
      P7-5 tests: verifies extents, detects on-disk corruption
      via direct pwrite + remount + scrub, mid-extent blocks
      charge to OK in multi-block extent). Single-replica corner
      of bptr.tla — full replica-walk + rewrite awaits extent
      record's replica-list extension.
- [ ] CAS tier — pending; needs extent layer + integration.
- [x] Send / recv — landed P7-7 (`a42d84d`).
- [x] Reflinks — landed P7-16 (`76ce44f`); cross-dataset deferred
      per ARCH §11.12.3 same-key requirement.
- [ ] Migration engine — pending; needs CAS tier.

## ROADMAP §10.2 exit criteria

Status: untouched. Phase 7 not yet entered.

- [ ] Cold-tier dedup achieves target 3-5× on VM-image test set.
- [ ] Migration policy heuristic produces reasonable hot/cold
      placement on synthetic workloads.
- [ ] Send + receive roundtrip preserves data + metadata +
      snapshots.
- [ ] Reflink is O(extent count) not O(data size).

## Operational notes

- Pre-work chunks landed into the v2 tree under `src/cdc/` with
  CMake target; participate in the standard test matrix (default
  + ASan + TSan).
- P7-1 spec scaffold landed; no STM_UB_VERSION bump (spec-only).
- P7-2 (extent C impl) WILL bump STM_UB_VERSION when persistence
  comes in — likely 11→12 when the extent btree's value layout
  is committed. Format-break user signoff required per CLAUDE.md.
- Audit-per-change pattern: R34 closed P7-2 at `433d2dd`. R35
  reserved for the next P7 chunk.
