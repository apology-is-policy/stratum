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
- [ ] Send / recv — pending; needs extent layer + birth-txg from
      snapshots (already in place from P6).
- [ ] Reflinks — pending; needs extent layer + refcount-bump path.
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
