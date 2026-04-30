# Stratum v2 — technical reference

This document is the **as-built** reference for Stratum v2. It
describes what exists in the v2 tree today, where the relevant code
lives, which invariants the TLA+ specs pin, and how the subsystems
compose. It is not a roadmap and not a design document — see
`docs/ARCHITECTURE.md` for design intent and `docs/ROADMAP-V2.md`
for phased scope.

## How to read this

The reference is split by subsystem, one file per layer of the stack.
Each file follows the same template:

- **Purpose** — one paragraph on what the layer does and where it
  sits in the stack.
- **Public API** — every exported function with its contract.
- **Implementation** — structure + invariants + known caveats.
- **Spec cross-reference** — TLA+ modules that pin invariants for
  this layer; SPEC-TO-CODE mapping entries.
- **Tests** — which suites exercise the layer and what they cover.
- **Status** — what's implemented today vs. what's stubbed or
  deferred. Commit hashes cite the landing points.

When a section describes a detail enforced by a spec, the spec's
action / invariant name is in `backticks`. When a section cites a
file, the form is `path/to/file.c:line` so editors can jump there.

## Audience

- Engineers landing changes to the subsystem under discussion.
- Reviewers validating that a change matches the documented contract.
- Auditors checking that invariants still hold.

If you are here to learn Stratum from scratch, start with
`docs/VISION.md` → `docs/ARCHITECTURE.md` → here. This reference
assumes you know what a Bε-tree is and why we want PQ-hybrid wrap.

## Snapshot

- **Tip**: post-R65-hash-fixup. Substantive `5ed1390` +
  R65 close `f81dbb1`.
  **P7-CAS-14 — per-COLD-read property cache. Closes R63 P3-2
  forward-noted micro-opt by adding a per-sync cache of the
  effective `STM_PROP_PROMOTE_DECAY_WINDOW` keyed by dataset_id.
  Pre-P7-CAS-14 every successful COLD decrypt called
  `stm_dataset_effective_property` from inside
  `stm_sync_read_extent_locked`'s COLD branch — that lookup
  acquires `dataset_idx->lock` and walks the parent chain. On
  hot-COLD-read workloads (backup-replay scrub, cold-archive
  blob serving) this added a per-read mutex acquire + tree walk
  on the read fast path. The cache replaces this with a
  fixed-cap (`STM_SYNC_PROMOTE_CACHE_CAP = 64`) array of
  (dataset_id, decay_window) pairs stamped with the dataset_idx's
  property-mutation gen at fill time. On lookup: read the gen
  (atomic, no lock); if differs from observed → invalidate
  en masse; linear-scan for the dataset_id; on hit return the
  cached value (folding 0 → compile-time default); on miss
  fall back to the original `stm_dataset_effective_property`
  call + insert into cache. Eviction: refuse-new-on-full —
  pools beyond the cap see the slow path each time but remain
  correct. Invalidation: `dataset.c` adds an
  `_Atomic uint64_t prop_mutation_gen` field bumped on every
  successful `set_property` / `clear_property` /
  `set_pool_default` / `move`; new public accessor
  `stm_dataset_index_property_mutation_gen` reads it with
  relaxed ordering. Atomic load avoids contending on
  dataset_idx->lock from the read fast path. Cache is per-sync,
  accessed under sync->lock; mutations are serialized by
  dataset_idx->lock. The cache + bump are documented best-effort
  + race-tolerant per R62 + R63 audits — a stale window value
  yields a stale heuristic decision, not a soundness violation.
  No format break (no on-disk surface change). property.tla
  unchanged (cache is a sync-side optimization). cas.tla
  unchanged (heuristic state, not load-bearing). **No spec
  extension required.** test_dataset 61 → 62 (+1 P7-CAS-14
  gen-counter test verifying bump on each mutation type +
  no-bump on idempotent operation + no-bump on failed mutation +
  NULL-defensive read). test_fs 146 → 149 (+3 P7-CAS-14
  cache-invalidation tests covering set_property,
  clear_property, set_pool_default — each verifies a stale
  cache would yield the WRONG counter value, so the test fails
  loudly if invalidation is missing). 35 ctest suites green
  default + ASan + TSan in isolation. Spec posture unchanged:
  21 modules / 25 fixed cfgs / 34 buggy cfgs.**
  Prior P7-CAS-13 substantive `2de9a49` + R64 close `e3655ac` +
  hash fixup `dc55f6f` + test-seam cleanup `e8a6f94`.
  **P7-CAS-13 — fs-level dataset property wrappers. Closes R63
  P3-4 forward-noted ergonomic gap by adding production-shape
  public APIs `stm_fs_set_dataset_property`,
  `stm_fs_clear_dataset_property`,
  `stm_fs_effective_dataset_property`, and
  `stm_fs_set_dataset_pool_default`. Pre-P7-CAS-13 the only
  callable path was via the test seam
  (`stm_fs_sync_for_test` → `stm_sync_dataset_index` → call the
  dataset.c API directly), bypassing `fs->lock` + the wedged/RO
  guards. The wrappers are thin pass-throughs — take fs->lock,
  apply FS_GUARD_WRITE (mutators) or FS_GUARD_READ (effective
  reader), get the dataset_idx via `stm_sync_dataset_index`,
  delegate to the dataset.c API. Lock posture: fs->lock →
  dataset_idx mutex (`stm_sync_dataset_index` is a pure pointer
  load, takes no sync-layer lock). dataset.c never re-enters
  sync.c or fs.c, so the acquisition is leaf-safe. The reader
  uses the established uniform out-param
  contract (zero-init `*out_value` BEFORE arg validation, so
  callers observing on STM_EINVAL/STM_EWEDGED still see a
  defined value). Effective reader is allowed on RO mounts
  (read-only check is FS_GUARD_WRITE-specific); mutators refuse
  RO with STM_EROFS. Persistence: the wrapper writes through the
  same `dataset_idx` that the next `stm_fs_commit` /
  `stm_fs_unmount` flushes — no side cache, no replay state. No
  format break (no on-disk surface change); no spec extension
  (composition over the dataset.c API which is already pinned by
  property.tla). test_fs grows 139 → 146 (7 P7-CAS-13 tests:
  basic set/get/clear roundtrip; pool-default routing;
  arg-validation matrix including OOR property + unknown
  dataset id; wedged-refused for all four wrappers + uniform
  out-param zero-init; RO-refuses-mutators-allows-effective;
  IMMUTABLE set-once enforcement propagates; persists through
  commit+remount). 35 ctest suites green default + ASan + TSan
  in isolation. Spec posture unchanged: 21 modules / 25 fixed
  cfgs / 34 buggy cfgs.**
  Prior P7-CAS-12 substantive `0523cae` + R63 close `473c7fa` +
  hash fixup `aff8eb7`.
  **P7-CAS-12 — promote-decay-window per-dataset property. Format
  break STM_UB_VERSION 21 → 22: STM_PROP_COUNT 4 → 5, adding
  `STM_PROP_PROMOTE_DECAY_WINDOW` (INHERITABLE; per-dataset
  override for the per-COLD read-frequency counter's decay
  window in txgs). Effective value 0 = use compile-time default
  (`STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS = 1024`); non-zero
  = use that window. The bump call site at
  `stm_sync_read_extent_locked`'s COLD branch resolves the
  effective property at each successful decrypt and passes the
  result to `stm_extent_record_promote_read_hit`. Lock order is
  preserved: sync->lock (held) → dataset_idx mutex (acquired
  here); dataset.c never calls back into sync. Dataset value
  layout grows past local_value[]: origin_snap_id moves from
  offset 64 to 72; DS_VAL_FIXED 72 → 80. Pool-defaults value
  length grows from 32 to 40 bytes. v21 pools refused at v22
  mount via uniform STM_EBADVERSION (no in-place forward-compat —
  same posture as v19→v20 and v18→v19). The `STM_PROP_TIERING`
  semantics from P7-CAS-8 are unchanged; `STM_PROP_PROMOTE_DECAY_WINDOW`
  composes orthogonally — TIERING gates whether a dataset
  participates at all in the migration/promotion policy passes,
  while PROMOTE_DECAY_WINDOW tunes the read-frequency heuristic
  for datasets that already opted in. property.tla unchanged
  (parametric over Properties; existing INHERITABLE-class
  invariants already cover the new property). cas.tla unchanged
  (the bump logic is heuristic state, not load-bearing). **No
  spec extension required.** test_dataset grows 59 → 61 (2 new
  P7-CAS-12 tests: chain-inheritance + zero-as-legal-value, plus
  kind-classifier extension); the existing
  `dataset_persist_commit_load_roundtrip` exercises slot-4 in the
  v22 layout. test_fs grows 135 → 139 (4 new P7-CAS-12 tests:
  small-window-resets-counter, default-preserves-baseline,
  inherits-from-parent-dataset, local-zero-resolves-to-default).
  test_pool UB-version assertion bumped 21 → 22. 35 ctest suites
  green default + ASan + TSan in isolation. Spec posture
  unchanged: 21 modules / 25 fixed cfgs / 34 buggy cfgs.**
  Prior P7-CAS-11 substantive `51c5cc6` + R62 close `ee00bdf` +
  hash fixup `e5b5238`.
  **P7-CAS-11 — promotion (cold → hot) heuristic v1. Format
  break STM_UB_VERSION 20 → 21: extent record value layout
  grows 96 → 108 bytes with `read_count` (le32 at offset
  96..100) + `last_read_gen` (le64 at offset 100..108). HOT
  extents always have both fields == 0 with on-disk decoder
  anti-tamper enforcement; COLD extents carry the windowed-
  count state. Counter increments via
  `stm_extent_record_promote_read_hit` from
  `stm_sync_read_extent_locked`'s COLD branch on every
  successful chunk decrypt — best-effort + race-tolerant.
  Windowed-count semantics with hardcoded
  `STM_SYNC_PROMOTE_DECAY_WINDOW_DEFAULT_TXGS = 1024` (renamed
  from `STM_SYNC_PROMOTE_DECAY_WINDOW_TXGS` by P7-CAS-12; the
  per-dataset override knob now lives in
  `STM_PROP_PROMOTE_DECAY_WINDOW`): counter resets
  to 1 if `current_gen - last_read_gen > window`, else
  saturating-increments (UINT32_MAX clamp). New extent-tree API
  `stm_extent_promote_swap_to_hot` (atomic cold→hot, returns
  dropped hash for caller to route through cas_deref) — the
  inverse of `stm_extent_migrate_to_cold`. New sync APIs
  `stm_sync_promote_to_hot` (per-ino driver: walks COLD
  extents, decrypts each via CAS, re-encrypts under fresh
  paddrs + dataset CURRENT DEK, atomic swap, deref) +
  `stm_sync_promote_policy_collect` (heuristic candidate
  collector: max(read_count) + max(last_read_gen) per ino
  filtered by min_read_count + cutoff_recency_gen). New fs APIs
  `stm_fs_promote_to_hot` + `stm_fs_promote_policy_step` (v1
  heuristic with INTERRUPTIBLE pass + hard/soft error
  classification + budget caps; mirrors
  `stm_fs_migrate_policy_step`'s shape exactly) +
  `stm_fs_promote_policy_pass_all` (multi-dataset wrapper
  filtered by effective `STM_PROP_TIERING`; same property gates
  promotion AND migration — opt-in is symmetric). Composition
  over `cas.tla::RehydrateOnWrite` — the cold→hot transition is
  identical to the existing auto-rehydrate-on-write path; only
  the trigger differs (frequent reads vs overlapping write).
  **No spec extension required.** Storage cost: promotion
  REVERSES the dedup compression — a chunk shared by N cold
  extents becomes 1 HOT extent + a CAS chunk at refcount=N-1,
  raising storage by 1×chunk_len per promoted extent. The
  heuristic must justify the doubling via expected read rate.
  test_fs grows 125 → 135 (10 new P7-CAS-11 tests:
  cold-read-counter increments, promote-to-hot basic,
  min-read-count blocks, persists across mount, no-cold returns
  ENOENT, max_inos budget, pass_all filtered by TIERING, arg
  validation, decrements CAS refcount, wedged refused).
  test_pool UB-version assertion bumped 20 → 21. 35 ctest suites
  green default + ASan + TSan in isolation. Spec posture
  unchanged: 21 modules / 25 fixed cfgs / 34 buggy cfgs.**
  Prior P7-CAS-10 substantive `21449cc` + R61 close `bebf4b7` +
  hash fixup `46328a3`.
  **P7-CAS-10 — out-of-band chunk store wire shape. Closes the
  on-wire dedup gap from P7-CAS-9. Wire format break
  STM_SEND_VERSION 1 → 2: new `STM_SEND_REC_CHUNK = 4` record
  kind ships each unique cold-content hash exactly once
  (32-byte BLAKE3-256 hash + plaintext); COLD EXTENT body
  shrinks from `64 + len` to a fixed 64 bytes (32-byte meta +
  32-byte content_hash, no plaintext follows). The framing-
  header `STM_SEND_FLAG_COLD` bit is preserved (signals the
  new body shape). New 3-API sync split:
  `stm_sync_recv_cold_chunk(s, hash, plain, plain_len)` —
  BLAKE3-verifies the wire hash against the re-hash of the
  received plaintext (same fail-fast position as
  `stm_sync_recv_cold_extent`'s step 1), then calls
  `cas_chunk_intern_locked` (lookup-or-insert with refcount
  bump);
  `stm_sync_recv_cold_extent_ref(s, target_ds, ino, off, len, hash)` —
  cas_lookup must HIT (defensive against the wire-protocol
  invariant being violated; receiver also enforces it earlier
  via chunks_seen membership), cas_ref + stm_extent_write_cold
  + cas_deref rollback on extent_write_cold failure;
  `stm_sync_recv_cold_chunk_release(s, hash)` — cas_deref
  under sync->lock, deliberately doesn't refuse on wedged or
  read-only because recv_close needs to drain regardless. Sender
  plan precomputed at send_init after the cas_lookup pass:
  walks captured extents in (ino, off) order, dedupes by
  content_hash via O(N²) memcmp scan, builds `chunk_plan[]` of
  source extent indices (one per unique hash, pointing at the
  first extent in iteration order with that hash). Cursor logic
  in `stm_send_next` dispatches HEADER → CHUNKs (positions
  1..n_chunk_plan) → EXTENTs (HOT or COLD by hash) → END. New
  `emit_chunk_locked` mirrors P7-CAS-9's
  `read_decrypt_cold_chunk_plaintext` decrypt shape but emits
  body = 32-byte hash + plaintext directly. Receiver tracks
  per-stream `chunks_seen` (dynamic byte array of 32-byte
  hashes); `apply_chunk` adds the hash to the set after a
  successful intern; `apply_extent` COLD branch enforces
  membership before dispatching to `recv_cold_extent_ref`;
  `recv_close` drains via `recv_cold_chunk_release` calls.
  Stream-ordering invariant: every COLD EXTENT's hash MUST be
  preceded by a CHUNK record in the same stream — sender
  enforced (chunk_plan precedes extents in cursor order),
  receiver enforced (chunks_seen membership check at
  apply_extent COLD time, STM_ECORRUPT on miss). Lifecycle
  invariant: every successful CHUNK MUST be balanced by a
  release at recv_close — without the drain, the per-CHUNK
  intern bump leaks at refcount = (extent refs) + 1 which
  auto_gc won't reclaim. Pre-populated target HIT path: if the
  receiver already has the chunk, the CHUNK arrival HITs and
  bumps refcount; recv_close's drain balances that bump; the
  EXTENT bump persists. Final receiver refcount =
  (pre-existing) + (new extents in stream). Orphan CHUNK
  handling: a CHUNK with no referencing EXTENT in the same
  stream sits at refcount=1; recv_close decrements to 0; next
  commit's auto_gc reclaims. Sender at v1 doesn't emit orphan
  CHUNKs but the receiver tolerates it. Wire-bytes math: at
  high dedup ratio (N referencing extents per K unique chunks),
  the cold portion ships K × (chunk_plain + ~80) + N × 80 bytes
  vs P7-CAS-9's N × (chunk_plain + ~80) bytes; savings =
  (N-K) × chunk_plain. For 128 KiB chunks with 10× dedup,
  savings ≈ 9 × 128 KiB per 10 extents = 1.15 MiB. v1 streams
  refused at v2 receivers with STM_EBADVERSION at HEADER apply.
  Composition: pure callers of the same primitives —
  `cas_chunk_intern_locked`, `stm_cas_ref`, `stm_cas_deref`,
  `stm_extent_write_cold`. The new wire-protocol invariants
  (every COLD EXTENT preceded by CHUNK; no duplicate CHUNK in
  stream) are wire-level, enforced at recv layer; the
  underlying CAS state machine is unchanged. **No spec
  extension required.** test_send_recv grows 23 → 33 (10 new
  P7-CAS-10 tests: chunk-store roundtrip single, deduped 3
  cold extents → 1 chunk + 3 EXTENT, mixed HOT+COLD with
  dedup, recv refuses COLD without prior CHUNK, recv refuses
  duplicate CHUNK, orphan CHUNK reclaimed, pre-populated
  target balances, recv refuses CHUNK before HEADER, v1
  stream refused, CHUNK with unknown flag bits refused; +2
  P7-CAS-9 hash-mismatch tests retargeted to CHUNK record
  since COLD EXTENT no longer carries plaintext). 35 ctest
  suites green default + ASan + TSan in isolation. Spec
  posture unchanged: 21 modules / 25 fixed cfgs / 34 buggy
  cfgs. No UB format break — STM_UB_VERSION = 20 preserved
  (only STM_SEND_VERSION on-wire changes).**
  Prior P7-CAS-9 substantive `f398f7f` + R60 close `501d7dd` +
  hash fixup `fa90f6f`.
  **P7-CAS-9 — send/recv with cold extents. Wire-format
  extension: a new `STM_SEND_FLAG_COLD` bit on the EXTENT record
  framing header signals the extended COLD body shape (32-byte
  meta + 32-byte BLAKE3-256 content_hash + plaintext, vs. HOT's
  32-byte meta + plaintext). The wire still carries plaintext
  for COLD extents (no on-wire dedup in v1) but the receiver
  preserves the cold-dedup property at rest: two cold extents
  with identical content collapse to one CAS entry on the
  target with refcount=2. New public sync API
  `stm_sync_recv_cold_extent(s, target_ds, ino, off, len,
  *claimed_hash, *plain, plain_len)` does the receiver-side
  application: BLAKE3-verify the wire hash against re-hash of
  received plaintext (catches a malicious or buggy sender
  lying about the hash, which would violate the CAS invariant
  "hash X stores bytes hashing to X"), CAS lookup-or-insert via
  `cas_chunk_intern_locked` (mirrors `stm_sync_migrate_to_cold`'s
  per-chunk shape; reserves fresh paddrs + AEAD-encrypts under
  target's pool metadata key + stm_ad_cas on miss), insert COLD
  extent record with target's current_gen + dataset CURRENT
  key_id + origin = (target_ds, ino, off). Send-side: extends
  send_extent_meta with kind + content_hash + cas_paddrs +
  cas_gen captured at send_init from the source's CAS index.
  New helper `read_decrypt_cold_chunk_plaintext` mirrors
  `read_decrypt_extent_plaintext`'s shape but uses the pool
  metadata key + stm_ad_cas. `send_collect_cb` now accepts
  COLD extents (the prior `n_replicas < 1` STM_ECORRUPT check
  applied unconditionally and would have refused the send;
  COLD extents legitimately have n_replicas == 0 in the extent
  record). Cold AEAD nonce + AD shape match
  `stm_sync_read_extent_locked`'s COLD branch. Receiver-side
  flag-mask validation (`STM_SEND_FLAG_KNOWN_MASK`) refuses
  unknown bits with STM_ECORRUPT — protocol-evolution
  discipline. Composition over `cas.tla::MigrateToCold` (the
  data plane is identical to migrate's MISS branch when the
  target lacks the chunk, IDENTICAL to migrate's HIT branch
  when the target already has it). No spec extension required
  — receiver is a pure caller of the existing migrate
  primitives. test_send_recv grows 14 → 23 (5 P7-CAS-9 primary
  tests + 4 R60 regressions: pre-populated target HIT path,
  unprovisioned-target rollback, hash-mismatch state-clean,
  replica-fallback structural). 35 ctest suites green default
  + ASan + TSan in isolation. Spec posture unchanged: 21
  modules / 25 fixed cfgs / 34 buggy cfgs. No format break —
  STM_UB_VERSION = 20 preserved. R60 audit verdict: 0 P0 + 0
  P1 + 1 P2 + 5 P3 — all addressed inline (P2-1 send_init's
  benign concurrent-reclaim race surfaces as STM_EBUSY not
  STM_ECORRUPT; P3-1 corrected the misleading "chunk stays
  alive" comment in send.c; P3-2 documented the COLD-path
  stale-paddr caveat in send_recv.h; P3-3 cas_chunk_intern
  HIT branch validates cas_rec.length against plain_len; P3-4
  send_collect_cb refuses COLD with n_replicas != 0; P3-5
  added 4 new tests covering pre-populated HIT, unprovisioned
  rollback, hash-mismatch state-clean, replica-fallback).**
  Prior P7-CAS-8 substantive `8410198` + R59 close `c2323fe` +
  hash fixup `019ed4d`.
  **P7-CAS-8 — per-dataset `STM_PROP_TIERING` opt-in + multi-
  dataset migration-policy wrapper. Format break STM_UB_VERSION
  19 → 20: `STM_PROP_COUNT` grows from 3 to 4, adding
  `STM_PROP_TIERING` (INHERITABLE — children inherit parent's
  preference unless locally overridden). Dataset value layout
  grows past the local_value[] tail: origin_snap_id moves from
  offset 56 to offset 64; `DS_VAL_FIXED` 64 → 72. Pool-defaults
  value length 24 → 32 bytes. v19 pools refused at v20 mount via
  uniform STM_EBADVERSION (same posture as v17→v18 and v18→v19
  bumps). New public API
  `stm_fs_migrate_policy_pass_all(fs, *params, *out_stats)`
  walks every PRESENT dataset, resolves effective TIERING via
  `stm_dataset_effective_property`, and runs the per-dataset
  policy step on every dataset that resolves a non-zero value.
  Budget shape: `max_inos` and `max_bytes` are SHARED across
  enabled datasets (the wrapper decrements caps by the running
  total before each per-step call); `min_age_txgs` is uniform
  per-dataset. New aggregate stats struct
  `stm_fs_migrate_policy_pass_all_stats` carries
  `datasets_visited / eligible / migrated` plus the aggregated
  per-dataset counters. Lock posture: takes fs->lock during
  dataset enumeration + property resolution, drops it before
  per-step invocation; the orchestrator is INTERRUPTIBLE
  between datasets (concurrent writers / admin calls
  interleave). Hard errors abort the orchestrator; soft errors
  recorded in `last_err / last_err_dataset_id / last_err_ino`
  and the orchestrator continues. Composition over P7-CAS-7's
  per-step primitive — no new state-machine semantics, no spec
  extension required. property.tla unchanged (parametric over
  Properties; existing INHERITABLE-class invariants already
  cover the new property). test_fs grows 116 → 125 (7 P7-CAS-8
  primary tests + 2 R59 regressions: soft-error-then-clean
  continuation via bdev fault injection; wedged refusal).
  test_dataset grows 57 → 59 (TIERING classification +
  inheritance + persistence roundtrip; existing
  `dataset_persist_commit_load_roundtrip` extended to exercise
  STM_PROP_TIERING through the v20 encode/decode). 35 ctest
  suites green default + ASan + TSan in isolation. Spec posture
  unchanged: 21 modules / 25 fixed cfgs / 34 buggy cfgs. R59
  audit verdict: 0 P0 + 0 P1 + 1 P2 + 3 P3 — all addressed
  inline (P2-1 unconditional hard-error override of
  `stats->last_err` matches the per-step primitive's R58 P3-4
  contract; P3-1 dataset.h on-disk value-layout doc updated for
  v20; P3-2 persistence roundtrip extended to exercise
  STM_PROP_TIERING; P3-3 dropped unreachable width-saturation
  branch in budget arithmetic).**
  Prior P7-CAS-7 substantive `1d5255c` + R58 close `231e5ff` +
  hash fixup `80d6ba0`.
  **P7-CAS-7 — migration-policy heuristic v1 (NOVEL #6 v1 in
  CLAUDE.md mission numbering / NOVEL #3.3's "Migration engine:
  heuristic v1"). First concrete user of the P7-CAS-2 migration
  data plane (which had been manual-trigger only since 2026-04-26).
  New public API `stm_fs_migrate_policy_step(fs, dataset_id,
  *params, *out_stats)` runs an age-based candidate selection over
  a single dataset and migrates eligible inos within a per-pass
  budget. v1 heuristic: an ino is eligible iff every live extent
  at (ds, ino) is HOT and the newest extent's `link_gen` is at
  least `min_age_txgs` behind the sync layer's current_gen at the
  call site. Mixed (HOT+COLD) inos are skipped — partial
  migration is not v1 scope. Empty / fully-COLD inos are skipped
  silently. Per-pass budgets: `max_inos` (count cap, 0=unlimited)
  + `max_bytes` (snapshot-at-collect bytes cap, 0=unlimited);
  budget is checked BEFORE each candidate's migrate so the cap is
  best-effort, not a hard ceiling — concurrent shrinks/extends
  between collect and migrate cause `bytes_migrated` to drift.
  Lock posture: takes fs->lock during candidate collection, drops
  it between collection and per-ino migrate. Each per-ino migrate
  re-acquires fs->lock fresh — the pass is INTERRUPTIBLE
  (concurrent writers / admin calls interleave). Hard errors
  (STM_EWEDGED / STM_EROFS / STM_ENOMEM) abort the pass and bubble
  up; soft errors (STM_EBADTAG / STM_EIO / STM_ENOSPC / STM_ECORRUPT)
  are recorded in `out_stats->{last_err, last_err_ino}` and the
  pass continues — a single corrupt file does not stall the whole
  tier. New sync-layer helper
  `stm_sync_migrate_policy_collect(s, ds, cutoff_link_gen, *out_cands,
  *out_n_cands, *out_inos_visited)` does the read-only walk under
  sync->lock — exposed publicly so future orchestrators can preview
  candidates without performing migration (RO handles can run
  collect; only the migrate step refuses RO). Composition over
  `cas.tla::MigrateToCold` — no new state-machine semantics, no
  spec extension required. v1 limitations + future work documented
  in `reference/15-cas.md`'s new "Migration policy (P7-CAS-7)"
  subsection. test_fs grows 102 → 116 (11 P7-CAS-7 primary tests
  + 3 R58 regressions: multi-dataset filtering, reserved-field
  rejection, soft-error mid-pass continuation via bdev fault
  injection). 35 ctest suites green default + ASan + TSan in
  isolation. Spec posture unchanged: 21 modules / 25 fixed cfgs /
  34 buggy cfgs. No format break — STM_UB_VERSION = 19 preserved.
  R58 audit verdict: 0 P0 + 0 P1 + 0 P2 + 7 P3 — green signal;
  all 7 P3s addressed inline (P3-1 zero-init out_stats before
  validation; P3-2 same fix on the sync-layer collect helper;
  P3-3 documented the out_inos_visited error contract; P3-4 stamp
  last_err / last_err_ino on hard-error abort for operator
  diagnostics; P3-5 added soft-error mid-pass regression test
  using stm_bdev_inject_fail_after; P3-6 added multi-dataset
  filtering test; P3-7 reject non-zero `_reserved0` to lock down
  forward compat).**
  Prior P7-CAS-6 substantive `b1a4816` + R57 close `8412194` +
  hash fixup `ee69459`.
  **P7-CAS-6 — scrub-orchestrator wrapper. Adds public API
  `stm_sync_scrub_step_with_cas_gc(s, sc, *out_cas_gc_err)` that
  drives one `stm_scrub_step` and fires `stm_sync_cas_gc_sweep`
  on the RUNNING→COMPLETED state transition. Purely compositional
  on top of P7-CAS-5: no scrub-side API changes, no new locking,
  no spec change. The natural cadence for cold-tier reclamation
  in production scrub-runner orchestrators. Sweep status surfaced
  via the out-param (best-effort: a sweep failure doesn't fail
  the scrub step itself). Production pattern documented in
  `reference/15-cas.md`'s new Orchestration section. test_fs
  grows 97 → 101 (4 new tests: completion-fires-sweep, RUNNING-
  state-no-sweep, IDLE-state-no-sweep, arg validation). 35 ctest
  suites green default + ASan + TSan in isolation. Spec posture
  unchanged: 21 modules / 25 fixed cfgs / 34 buggy cfgs. R57
  audit forthcoming. Cold-tier orchestration is now end-to-end:
  in-commit sweep + out-of-band sweep + scrub-driven sweep all
  share the same `cas_auto_gc_sweep_locked` core under the
  P7-CAS-4 reordered semantics.**
  Prior P7-CAS-5 substantive `a97c870` + R56 close `cc180c9` +
  hash fixup `7813552`.
  **P7-CAS-5 — out-of-band CAS GC entry point. Adds public API
  `stm_sync_cas_gc_sweep(s)` exposing the (now-correct) P7-CAS-4
  reordered sweep to orchestrators outside `stm_sync_commit`.
  Takes `sync->lock` internally; safe from any context not already
  holding it. Implementation is a thin wedged/RO guard +
  `cas_auto_gc_sweep_locked(s)`. The out-of-band sweep stamps
  PENDING entries with `free_gen = s->current_gen` (the gen of
  the LAST committed sync); next `stm_sync_commit` reclaims via
  the alloc-tree sweep predicate. No spec change (cas.tla::GC's
  atomic remove-and-mark-freed semantics already cover both the
  commit-time and out-of-band invocation contexts). test_fs
  grows 91 → 97 (5 new tests: basic reclaim, no-work no-op,
  arg validation, RO refusal, persists-pending-across-commit,
  idempotent retry). 35 ctest suites green default + ASan + TSan
  in isolation. Spec posture unchanged: 21 modules / 25 fixed
  cfgs / 34 buggy cfgs. R56 audit forthcoming.**
  Prior P7-CAS-4 substantive `edc3b51` + R55 close `7399004` +
  hash fixup `18a2ba3`.
  **P7-CAS-4 — background-GC semantics + R51/R54 P3 closure round.
  Reorders `cas_auto_gc_sweep_locked` from "alloc_free first → cas_gc
  second" (P7-CAS-3) to "cas_gc first → alloc_free second" so a
  concurrent stm_cas_ref bump between Phase 1 capture and Phase 2
  cas_gc surfaces as STM_EBUSY → skip the entire tuple cleanly (no
  entry removal AND no paddr free; next sweep retries when refcount
  drops back to 0). Closes R51 P3-2 — silent-skip on EBUSY under the
  prior order leaked alive-entry's paddrs to PENDING, which would
  reissue to a new hot extent under a future without-sync->lock
  scrub-driven CAS GC → cas.tla::HotColdReplicasDisjoint violation.
  R51 P3-4: alloc_free now skips STM_DEV_STATE_FAULTED /
  STM_DEV_STATE_REMOVED devices (alloc_commit's per-device loop
  already skips them; symmetry keeps in-RAM and on-disk in
  lockstep). Spec extension to cas.tla: new variables
  `freed_paddrs` + `gc_in_flight`; atomic `GC` action that updates
  cas_entries + freed_paddrs in lockstep; two-step buggy actions
  `BuggyGcOldOrderFreePaddrs` + `BuggyGcOldOrderTryRemove` under
  `BuggyGcOldOrderSilentSkip = TRUE` modeling the race window;
  new invariant `LiveCASEntriesNotFreed` (no live cas entry's
  replicas overlap freed_paddrs, modulo `gc_in_flight` in-flight-GC
  tolerance). cas.cfg green at 3.23M states / depth 10 / ~5:33 wall
  (was 3.18M / 3:32; freed_paddrs growth absorbed). New
  `cas_gc_old_order_silent_skip_buggy.cfg` fires
  `LiveCASEntriesNotFreed` at depth 7. R54 P3-2 fix: pre-check
  capacity via new
  `stm_snapshot_index_cold_dead_list_reserve(idx, dataset_id,
  n_to_append, *out_can_accept)` API + sync.c bookends call it
  BEFORE `stm_extent_overwrite` / `stm_extent_truncate_into`;
  without the pre-check, a per-call STM_ENOSPC mid-bookend silently
  lost the deref obligation → permanent CAS leak. R54 P3-3:
  `stm_snapshot_cold_dead_list_count(snapshot_id == 0)` rejected
  with STM_EINVAL (consistency with rest of snapshot API). R54 P3-1:
  dead `else { should_deref = true; }` removed in both write_extent
  and truncate bookends (s->snap_idx unconditionally created at
  sync_create / sync_open, so the fallback was unreachable).
  test_fs grows 83 → 90 (7 new P7-CAS-4 tests covering reserve API +
  arg validation, full-snap ENOSPC for write+truncate, GC reorder
  happy path, refbumped-entry alloc-state preservation). 35 ctest
  suites green default + ASan + TSan in isolation. Spec posture:
  21 modules / 25 fixed cfgs / 34 buggy cfgs. No format break —
  STM_UB_VERSION = 19 preserved. R55 audit forthcoming.**
  Prior P7-CAS-4c substantive `dbadc63` + R54 close `223250b` +
  hash fixup `f34f0d1`.
  **P7-CAS-4c — snap_idx ↔ CAS hash refcount integration. Closes the
  P7-CAS-2 forward-noted deferral that snapshots-with-cold-extents
  could see dangling-hash reads after auto-GC reclaimed the chunk.
  Format break STM_UB_VERSION 18 → 19: snapshot value layout extends
  past the existing dead_paddrs[] tail with `cold_dead_count` (le32)
  + `cold_dead_hashes[N][32]`. New `STM_SNAP_COLD_DEAD_LIST_MAX = 256`
  cap + `STM_SNAP_HASH_LEN = 32`. New API
  `stm_snapshot_index_overwrite_cold_block(idx, ds, hash, *out_should_deref)`:
  if a most-recent PRESENT snap exists for `ds`, append `hash` to its
  cold-dead-list (out_should_deref=false, deref deferred to snap-
  delete); else (no snap), out_should_deref=true and caller calls
  `stm_cas_deref` directly. `stm_snapshot_delete` extended with two
  out-params (cold_hashes byte buffer + count) — caller iterates +
  derefs each hash. New observability accessor
  `stm_snapshot_cold_dead_list_count`. Wired into sync.c at the
  cold-record-drop bookends (write_extent + truncate) — both replace
  the unconditional `stm_cas_deref` with snap-aware routing. Spec
  extension to dead_list.tla: new `WriteCold` + `OverwriteCold`
  actions; SnapDelete drains snap_cold_dead → cold_dereffed; new
  invariants `ColdExtentsTrackedSomewhere` + `LiveColdDisjointFromDead`
  + `LiveColdDisjointFromDereffed` + `DereffedColdDisjointFromDead`
  + `ColdSingleOwnership`. Two new buggy variants
  (BuggyOverwriteColdForgetsDead, BuggyDeleteColdForgetsDeref) both
  fire ColdExtentsTrackedSomewhere. dead_list.cfg green at 4.11M
  states / depth 21 / 27s (was much smaller; cold-tier broadens the
  state space). All 5 buggy demos fire. Persistence: sp_encode_value
  + sp_decode_value handle the new tail; sp_validate_shadow gains a
  within-snap cold-hash uniqueness check (cross-snap collisions
  legitimate per spec). Atomic-swap on load + close + load_at error
  paths free both arrays. test_fs grows 77 → 83 (5 P7-CAS-4c tests +
  1 R54 P1-1 regression test: snap-holds-cold-after-overwrite,
  snap-delete-releases-cold-dead, no-snap-cold-overwrite-derefs-
  directly, snap-cold-dead-list-persists-across-mount, snap-intra-
  cow-shared-hash-no-leak, arg validation).
  test_snapshot.c + test_sync.c + bench_snapshot.c snap_delete
  callers updated to the new 6-arg signature. test_pool.c UB version
  assertion bumped 18 → 19. 35 ctest suites green default + ASan +
  TSan in isolation. Spec posture: 21 modules / 25 fixed cfgs / 33
  buggy cfgs (was 31 — added 2 cold-tier buggy cfgs). R54 audit:
  1 P1 + 0 P0 + 0 P2 + 3 P3 — P1-1 (within-snap dedup-defense scan
  in `stm_snapshot_index_overwrite_cold_block` + matching check in
  `sp_validate_shadow` rejected legitimate intra-COW shared-hash
  drops, silently losing CAS-deref obligations and leaving chunks
  unreclaimable) fixed inline by removing both scans + adding
  `fs_snap_intra_cow_shared_hash_no_leak` regression test
  (test_fs 82 → 83). P3-1 + P3-2 + P3-3 forward-noted as
  P7-CAS-4 deferrals (dead-fallback codepath, STM_ENOSPC at cap
  exhaustion, arg-validation drift).**
  Prior P7-CAS-4b substantive `ad6be38` + R53 close `b932714` +
  hash fixup `04809f8`.
  **P7-CAS-4b — FastCDC sub-chunking. Integrates `src/cdc/` (FastCDC,
  P7-prework idle since 2026-04) into `stm_sync_migrate_to_cold` so
  one HOT extent can migrate to N COLD chunks at content-defined
  boundaries. New per-stm_sync `stm_cdc cdc;` field initialized from
  `stm_cdc_default_params` (ARCH §6.9.4: 8 MiB avg / 2 MiB min /
  32 MiB max). New atomic 1-drop+N-insert primitive
  `stm_extent_migrate_to_cold_chunked` (pre-grow records[] capacity,
  in-place overwrite of src slot with chunks[0], append chunks[1..K-1])
  alongside the existing single-chunk `stm_extent_migrate_to_cold`.
  `migrate_one_extent_locked` rewrite: read+decrypt → FastCDC chunk
  → round boundaries to STM_UB_SIZE = 4 KiB grid via
  `round_chunk_boundaries` (round-to-nearest, drop collapsed
  boundaries, ensure last chunk >= STM_UB_SIZE) → per-chunk pre-flight
  via new `cas_chunk_intern_locked` helper (BLAKE3 + CAS lookup-or-
  insert with paddr reserve / encrypt+write / cas_insert on miss;
  cas_ref on hit) → atomic migrate (K=1 dispatches to old single API,
  K>=2 to chunked API) → drop-route src HOT replicas. Rollback walks
  completed chunks calling `stm_cas_deref` on each (CAS-miss inserts
  drop refcount → 0 → auto-GC at next commit; CAS-hit bumps undone).
  Default ARCH §6.9.4 params → K=1 for 128 KiB recordsize-cap extents
  (FastCDC min=2 MiB > 128 KiB) → behavior identical to P7-CAS-2.
  Tests override CDC params via new test-only seam
  `<stratum/sync_testing.h>::stm_sync_set_cdc_params_for_test` to
  exercise multi-chunk migration. cas.tla extended with
  `ChunkedMigrateToColdK2` action (K=2 specialization; K=1 covered by
  existing MigrateToCold; K>=3 composes by induction). Pre-existing
  clamp/invariant inconsistency in MigrateToCold's CAS-hit branch
  (refcount clamps at MaxRef but invariant doesn't account) closed
  via new `EntryAt(h).refcount < MaxRef` precondition. Spec green at
  3.18M states / depth 10 / 3:32 wall (was 2.5M states / depth 10
  / 40s — added action + cap precondition). All 6 buggy demos still
  fire. test_fs grows 72 → 77 (5 new chunked-migrate tests +
  multi-extent read helper since `stm_fs_read` is single-extent MVP).
  R53: 0 P0 + 0 P1 + 0 P2 + 10 P3 — green signal. P3-2 + P3-4 + P3-5
  + P3-7 + P3-8 fixed inline; P3-1 superseded by inline cap-bump
  (E->len/256 + 8 ≈ 520-entry margin); P3-3 mitigated by
  stm_cdc_init validation in sync_new; P3-6 + P3-9 + P3-10
  forward-noted as cosmetic / test-hardening / micro-opt deferrals.
  35 ctest suites green default + ASan + TSan in isolation
  (parallel sanitizer matrices time-out per primer's known-issue
  note). No format break — STM_UB_VERSION = 18 preserved.**
  Prior P7-CAS-4a substantive `a9e21f3` + R52 close `fe6ac61` +
  hash fixup `8717514`.
  **P7-CAS-4a — crossing-cold truncate. Lifts the STM_ENOTSUPPORTED
  refusal P7-CAS-2 placed on truncating ACROSS a cold extent
  (rec.kind == COLD AND rec.off < new_size < rec.off + rec.len).
  No new code paths needed: composes via cold-aware
  `stm_sync_read_extent_locked` (added P7-CAS-2) + the kept-prefix
  re-encrypt under fresh `(paddrs[0], current_gen)` HOT AEAD nonce
  via `stm_sync_write_extent_locked` + the cold_overlap_cb pre-scan
  + post-deref bookend (P7-CAS-2) which captures the cold extent's
  content_hash and `stm_cas_deref`s it after `stm_extent_overwrite`
  drops the cold record. Net effect: the crossing-cold case is now
  semantically equivalent to "rehydrate the prefix as HOT, drop the
  rest, deref the hash" — composes via cas.tla::RehydrateOnWrite +
  extent.tla::Write without a new spec action. test_fs grows
  70 → 72 (replaced `fs_truncate_refuses_cold_crossing` with
  `fs_truncate_crossing_cold_extent_basic`,
  `_persists_across_mount`, `_dedup_partial_release`). cas.tla
  unchanged. 35 ctest suites green default + ASan + TSan. No format
  break — STM_UB_VERSION = 18 preserved.**
  Prior P7-CAS-3 substantive `5e25cca` + R51 close `ee25ff6` +
  hash fixup `c124e55`.
  **P7-CAS-3 — closes R50 P2-1 + P2-3 forward-noted deferrals + adds
  cold-extent reflink (CAS-bump shape). (1) **R50 P2-1 paddr-leak fix**:
  Two-part. (1a) `cas_auto_gc_sweep_locked` moved BEFORE
  `stm_alloc_commit` in `stm_sync_commit`. The sweep's
  `stm_alloc_free` calls now produce PENDING(free_gen=target_gen)
  entries that `stm_alloc_commit` PERSISTS in the on-disk alloc
  tree (alloc_commit's own sweep predicate `free_gen<committed_gen`
  excludes our entries from this-cycle reclamation but the PENDING
  state IS durable). (1b) `stm_alloc_load_tree_at` extended with a
  pending_head rebuild scan (R51 P1-1 inline fix): post-deserialize
  walk emits one `pending_entry` per refcount=0 tree entry with
  `free_gen=root_gen`. Without (1b), unmount loses the in-RAM
  pending_head and the tree-resident PENDING entries are
  unreachable to alloc_commit's sweep — the cross-mount leak the
  R50 P2-1 close claim depends on. With (1a)+(1b), the next mount
  + commit reclaims; a crash between this commit's final UB and
  the next sync_commit no longer leaks paddrs.
  (2) **R50 P2-3 transactional sweep**: refactored
  `cas_auto_gc_sweep_locked` to a three-phase shape — Phase 1
  captures (hash, paddrs, n_paddrs) tuples via cas_iter; Phase 2
  alloc_frees per paddr with idempotent-tolerant pre-check (lookup
  → refcount=0 means already PENDING from prior partial sweep
  retry → skip); Phase 3 cas_gcs every captured hash. Phase 2
  failure aborts WITHOUT calling cas_gc — cas_idx state unchanged,
  retry safe via the idempotent-PENDING-skip path. STM_EBUSY
  (concurrent ref-bump via stm_sync_cas_index) and STM_ENOENT
  (concurrent gc) treated as Phase 3 skip cases. (3) **Cold-
  extent reflink (CAS-bump shape)**: `stm_sync_reflink`'s
  `reflink_collect_cb` now accepts COLD extents (was
  STM_ENOTSUPPORTED in P7-CAS-2 MVP). Phase 2 branches on `e->kind`:
  HOT calls `stm_alloc_ref` per replica; COLD calls `stm_cas_ref`
  per cold record. Phase 3 inserts via `stm_extent_reflink` (HOT)
  or `stm_extent_write_cold` (COLD) — the latter inheriting gen /
  key_id / origin from src so AEAD AD reconstructs identically
  across siblings. Rollback path symmetrically undoes both bump
  classes via cx-snapshot ordered alloc_free / cas_deref capped
  at hot_bumped / cold_bumped. test_fs grows 67 → 69 — replaces
  `fs_reflink_refuses_cold_source` with three positive tests:
  `fs_reflink_cold_extent_basic_share` (refcount=2 dedup),
  `fs_reflink_cold_extent_overwrite_diverges` (rehydrate on dst →
  refcount drops to 1; src still reads cold), and
  `fs_reflink_cold_extent_dst_must_be_empty` (STM_EEXIST pre-
  condition still enforced). cas.tla unchanged (cold-reflink
  composes via existing `BumpRef` / MigrateToCold's CAS-hit
  branch shape; no new spec action). 35 ctest suites green
  default + ASan + TSan in isolation. No format break —
  STM_UB_VERSION = 18 preserved. Spec posture 21/25/31
  unchanged.**
  Prior P7-CAS-2 substantive `91fff73` + R50 close `6839cf0` +
  hash fixup `44d0a80`.
  **P7-CAS-2 — migration / rehydrate / auto-GC data plane. Closes the
  second half of ARCH §6.9 / NOVEL #3 (the index foundation landed at
  P7-CAS). New public API `stm_fs_migrate_to_cold(fs, ds, ino)`
  drives a 3-phase per-extent pipeline: read+decrypt source HOT
  plaintext → BLAKE3-256 hash → CAS lookup-or-insert (allocator-
  fresh paddrs, AEAD-encrypt under `stm_ad_cas` onto fresh replicas
  on miss; `stm_cas_ref` bump on hit) → atomic hot→cold swap via
  new `stm_extent_migrate_to_cold` (preserves NoOverlapWithinIno
  across the transition) → drop-route source HOT replicas through
  `sync_drop_paddr_locked`. Auto-rehydrate on writes: the existing
  `stm_sync_write_extent_locked` pre-scans for any COLD extent
  overlapping the write target; after `stm_extent_overwrite` drops
  it, calls `stm_cas_deref` on the captured hash. Same pre-scan +
  post-deref bookend in `stm_sync_truncate`'s past-extent drop path.
  Crossing-COLD truncate + reflink-of-cold-source refused with
  STM_ENOTSUPPORTED (deferred to P7-CAS-3 to avoid coupling cold-
  aware read/slice into truncate's prefix-shrink + reflink-of-cold
  CAS-bump). New COLD-aware read branch in
  `stm_sync_read_extent_locked` resolves COLD extent → CAS entry →
  AEAD-decrypt under `stm_ad_cas` + metadata_key (no per-dataset
  DEK; CAS chunks are cross-dataset shareable per ARCH §7.6.3).
  Auto-GC sweep at `stm_sync_commit`: walks the CAS index for
  refcount=0 entries, calls `stm_cas_gc` per hash, routes returned
  paddrs through `stm_alloc_free` — closes R49 P2-2 forward-note
  about orphan paddrs on unmount-after-deref. Sweep runs BEFORE
  `stm_cas_index_commit` so the persisted btree reflects post-GC
  state. Migration is extent-granularity hashing for the MVP
  (one BLAKE3 hash per HOT extent → one CAS chunk; FastCDC sub-
  chunking is a P7-CAS-3+ refinement; the CDC layer at `src/cdc/`
  remains available but unused by the migration data plane in this
  chunk). Snapshots that capture cold extents are NOT supported
  (snap_idx doesn't track CAS hashes; auto-GC may reclaim chunks
  still referenced by a snapshot's view) — documented MVP
  limitation. 35 ctest suites green default + ASan + TSan in
  isolation. test_fs grows 54 → 66 with 12 new integration tests
  covering basic round-trip, dedup, distinct-content non-dedup,
  idempotency, persistence-across-mount, rehydrate-on-write,
  dedup-then-rehydrate-one (refcount math), truncate-drops-cold,
  arg validation, RO refusal, reflink-cold refusal, truncate-
  crossing-cold refusal. cas.tla unchanged (P7-CAS-2 is pure
  data-plane plumbing of the existing model); 21 modules / 25
  fixed cfgs / 31 buggy cfgs posture preserved.**
  Prior: P7-CAS foundation `8eba90a` + R49 close `61205c7` + hash
  fixup `3444422`.
  **P7-CAS cold-tier index foundation — closes the first half of
  ARCH §6.9 / NOVEL #3 (the index + persistence + format break);
  migration / rehydration paths follow in P7-CAS-2. New
  `src/cas/cas_index.c` module realizing `cas.tla` against an
  in-RAM linear-array shadow + persistent btree_store-backed
  Bε-tree on device 0. Public API: `stm_cas_index_create / _close /
  _current_txg / _advance_txg`, `stm_cas_insert / _ref / _deref /
  _gc`, `stm_cas_lookup / _iter / _count`, plus the persistence
  triple `_set_storage / _set_crypt_ctx / _load_at / _commit /
  _get_root / _get_gen / _verify`. ERRORCHECK mutex with
  must_lock / must_unlock contract — same shape as extent_index.
  Format break STM_UB_VERSION 17 → 18: adds
  `ub_cas_index_root_gen` (le64 at offset 3280) carved from the
  head of `ub_reserved` (which shrinks 784 → 776); the tree-root
  bptr field `ub_cas_index_root` itself was carved at v3 in the
  metadata-roots block (offset 288) but went unused until now.
  Tree's bp_kind is `STM_BPTR_KIND_CAS` (= 6, also carved at v3).
  Extent record value layout gains a 1-byte `kind` discriminator
  at on-disk offset 0 (0x01 = HOT, 0x02 = COLD): HOT shifts
  n_replicas from byte 0 to byte 1 with bytes 2..7 reserved zero;
  COLD replaces bytes 1..39 with reserved (1..7) + content_hash
  (8..39, BLAKE3-256). Bytes 40..95 (write_gen, dlen, clen_and_
  comp, key_id, origin triple, link_gen) are kind-independent.
  CAS index value layout (64 bytes): n_replicas (u8 at byte 0) +
  reserved (1..7) + paddrs[4] (8..39) + refcount (u64 at 40..47) +
  length (u64 at 48..55) + gen (u64 at 56..63). New AEAD AD struct
  `stm_ad_cas` (56 bytes — magic + version + pool_uuid +
  content_hash) per ARCH §7.6.3. New `stm_ad_cas_pack` packer.
  `compute_merkle_root` flows the CAS root csum through (the slot
  was reserved with zeros from earlier phases; first cold-tier
  commit populates it). sync_open's recompute equally uses
  `ub.ub_cas_index_root.bp_csum`. New cas.tla spec: 6 actions
  (WriteHot / MigrateToCold / RehydrateOnWrite / DeleteFile / GC /
  AdvanceTxg) + 9 invariants (TypeOK, CASIndexUnique,
  NoOverlapWithinIno, LengthPositive, BirthTxgBound,
  PaddrFreshness, RefcountConsistent, NoDanglingColdRef,
  HotColdReplicasDisjoint, CASReplicasDisjoint); 6 buggy demos
  (BuggyMigrateForgetsRefBump, BuggyMigrateWithoutDrop,
  BuggyGCRaceWithRef, BuggyRehydrateWithoutDeref,
  BuggyDeleteForgetsCASDeref, BuggyMigrateReusesHotPaddr) — each
  fires its expected invariant under TLC. cas.cfg green at 2.5M
  distinct states / depth 10 / 40s wall. New test suite
  `test_cas_index` with 20 unit tests (lifecycle, mutations,
  GC, iter, multi-step dedup composition); test_fs grows 52 → 54
  with 2 new integration tests covering format-time presence and
  cross-mount persistence of the CAS index. 35 ctest suites green
  default + ASan + TSan in isolation. Spec posture: **21 modules
  / 25 fixed cfgs / 31 buggy cfgs**.
  Migration / rehydration paths (cas.tla::MigrateToCold /
  RehydrateOnWrite at the C impl level, `stm_sync_migrate_to_cold`
  + auto-rehydrate-on-write) deferred to P7-CAS-2 — the spec +
  index layer + format break is the foundation; the data-plane
  pipeline that drives the index is its own chunk.**
  Prior: P7-16 reflinks `76ce44f` + R48 close `1951f65` + hash
  fixup `beabd83`.
  **P7-16 reflinks — closes the long-pending ARCH §11.12 surface
  (FICLONE-shape O(extent count) reflinks) at v1 MVP scope: same-
  dataset whole-file reflinks. New public API
  `stm_fs_reflink(fs, src_ds, src_ino, dst_ds, dst_ino)` bundles
  a 3-phase composition under sync->lock — collect src extents,
  bump `stm_alloc_ref` on every replica paddr, insert reflinked
  records via the new `stm_extent_reflink` with origin INHERITED
  from src. Format break STM_UB_VERSION 16 → 17: extent on-disk
  value 64 → 96 bytes adding `origin_dataset_id` (offset 64) +
  `origin_ino` (72) + `origin_off` (80) + 8 reserved bytes
  (88..95). The origin triple names the (ds, ino, off) at which
  the AEAD ciphertext was first encrypted; both reflink-siblings
  reconstruct AD from origin (rather than live ds/ino/off) so
  AEGIS-256 verify succeeds across the share. Spec replaces
  `LiveReplicasDisjoint` with `SharedReplicasAreCohabit`: paddr-
  share legitimate ONLY when the whole replica set + gen + key_id
  + origin tuple matches (catches partial overlap + whole-share-
  with-mismatched-tuple); new `OriginConsistentInBounds`
  (origin_off + len ≤ MaxFileBlocks). New extent.tla::Reflink
  action, new `BuggyReflinkRotatesOrigin` variant, new
  `reflink_rotates_origin_buggy.cfg` (fires at depth 4 / 595
  states). New `DisableReflink` cfg toggle keeps extent.cfg's
  bumped bounds (838,164 states / ~1m wall) tractable;
  extent_keyids.cfg now exercises Reflink with MaxDatasets=2
  (~3.6M states / ~4m wall). C-impl AD reconstruction at
  read / scrub / send paths sources from `rec.origin_*` instead
  of live identity; `send_extent_meta` gains origin fields so the
  per-extent send wire (post-snapshot capture) reconstructs the
  same AD as the live read path. ex_validate_shadow's cross-
  record disjointness replaced with cohabit classification (any-
  share → must be whole-set + matching gen + key_id + origin
  tuple, else STM_ECORRUPT). Cross-dataset reflinks deferred per
  ARCH §11.12.3 same-key requirement; refused with new STM_EXDEV
  error code (-18). 7 new test_extent_index unit tests + 9 new
  test_fs integration tests; test_extent_index 62 → 69; test_fs
  42 → 52 (post-R48 P1-1 regression); test_send_recv +1 (post-R48
  P0-1 regression). 34 ctest suites green default + ASan + TSan
  in isolated runs (-j2).
  R48 fold: P0-1 added `link_gen` field (separate creation-gen
  vs AEAD-gen) so incremental send catches reflinks in (S_from,
  S_to]; P1-1 made `sync_drop_paddr_locked` refcount-aware so
  reflink + snap + dual-overwrite no longer hits R33 P2 single-
  ownership; P2-1 rewrote Phase 3 rollback to walk the snapshot
  directly (no leak on delete_file failure); P2-2 added origin_off
  + dlen overflow check at decode; P3-1 + P3-2 stale comment +
  dead variable. link_gen uses the v17 reserved bytes 88..95;
  format-fold within v17, STM_UB_VERSION stays 17. extent_keyids
  .cfg state space 3.6M → 8.7M (~2.4x), still tractable at ~12m
  wall under TLC.**
  Prior: P7-15 repair-log persistence `c02cba8` + R47 close
  `82fe30e` + hash fixup `c6d9717`.
  **P7-15 repair-log persistence — closes R38 P3-1 (the long-
  deferred audit gap from P7-6 noting that the production scrub
  β cb's replica rewrites had no on-disk audit trail per ARCH
  §7.15.4 / bptr.tla::LogIntegrity). New `src/repair_log/`
  module implements a single-leaf btnode-encoded, plaintext +
  Merkle-covered append-only log keyed by monotonic seq_id with
  a 32-byte fixed value layout (timestamp_ns + target/source
  paddrs + replica indices + corruption type + verification
  result). Three new uberblock fields carved from `ub_reserved`:
  `ub_repair_log_root` (stm_bptr at offset 3200), `ub_repair_log_
  root_gen` (le64 at 3264), `ub_repair_log_next_seq` (le64 at
  3272); `ub_reserved` shrinks 864 → 784 bytes. New bptr kind
  `STM_BPTR_KIND_REPAIR_LOG = 11`. Scrub β cb gains per-rewrite
  emit (both success and failure paths); Phase 1 split adds a
  parallel `replica_io_err[]` array so the bptr.tla read_outcome
  tag (CSUM_FAIL vs IO_ERR) propagates to the log entry's `type`
  field. Format break STM_UB_VERSION 15 → 16. R47 P2-1 folded
  `repair_log_csum` into `compute_merkle_root` as the 7th input
  so an offline tamper of the audit trail surfaces as a Merkle
  mismatch at mount (closes the asymmetry vs keyschema's existing
  Merkle coverage). R47 fixes inline: P2-1 (Merkle gap) + P3-1
  (cap collision halts sync_commit — moved to emit-time STM_ERANGE
  with `STM_REPAIR_LOG_MAX_ENTRIES = 2048` constant) + P3-2
  (tampered paddr device → STM_ECORRUPT not STM_EINVAL) + P3-3
  (iter docstring claim) + P3-4 (iter cb re-entry warning).
  P3-5 (reference-doc gap) deferred to this hash-fixup per the
  three-commit pattern (R42 P3-2 precedent). 34 ctest suites
  green default + ASan + TSan; new test_repair_log suite (7
  tests) + 1 new test_fs integration test. test_crash_inject
  timeout bumped 180s → 300s for TSan headroom.**
  Prior: P7-14 snap chain-ordering regression `01b5233` + R46
  close `485f0ef` + hash fixup `9dd2d9a`.
  **P7-14 snap chain-ordering regression — closes R40 P3-3 (the
  long-standing audit deferral noting there was no on-disk
  regression test for `sp_validate_shadow`'s
  `ChainExtentTxgOrdered` validator). New gated test-only API
  `stm_snapshot_create_for_test` lives in
  `<stratum/snapshot_testing.h>` and bypasses ONLY the R40 P2-1
  in-process check (all other arg validation runs); same shape
  as `stm_snapshot_create` minus the chain-ordering refusal.
  R40 P2-1's in-process check has its own test
  (`snap_create_in_process_chain_ordering_refused`); the on-disk
  validator path is exercised by
  `fs_snap_chain_inversion_on_disk_refused_at_mount` — full
  format → mount → install one valid + one chain-inverted snap
  via `_for_test` → fs_commit → unmount → remount → expect
  STM_ECORRUPT from sp_validate_shadow. Refactored
  `stm_snapshot_create`'s body into a static
  `snapshot_create_inner` helper that takes a `skip_chain_check`
  flag; both public functions collapse to one-line forwards
  (single source of truth for arg validation). R46 P2-1 hardened
  the test seam: gated `_for_test` symbol behind the new
  `STRATUM_BUILD_TESTING_HOOKS` CMake option (default ON for the
  in-tree dev/test build, opt-out for production via
  `-DSTRATUM_BUILD_TESTING_HOOKS=OFF`). Verified out-of-tree:
  with HOOKS=OFF, `nm libstm_snapshot.a` shows the production
  `stm_snapshot_create` only — the bypass symbol is absent from
  the archive, so production code can't even mistakenly
  extern-declare it. R46 fixes: P2-1 + P3-1 (tightened on-disk
  assertion to STM_ECORRUPT — propagation chain doesn't wrap)
  + P3-2 (prelude consolidation) + P3-3 (added NULL-name,
  NULL-out_id, oversize-name to _for_test test) + P3-4 (chain-
  inversion rejection added to reference/13-snapshot.md
  validator-rejection prose). No format break, no spec change.
  test_snapshot 41 → 43; test_fs 40 → 41. 33 ctest suites green
  default + ASan + TSan in isolated runs.**
  Prior: P7-13 fs_create_dataset `e6a751c` + R45 close `f30db5e`
  + hash fixup `5f65f37`.
  **P7-13 fs_create_dataset — bundles `stm_dataset_create_child` +
  `stm_sync_add_dataset_key` into one fs-level API under
  `fs->lock`. Removes the test_fs restriction "only ds=1 (root)
  writes work without explicit DEK install"; the freshly-created
  id is immediately usable for `stm_fs_write` / `stm_fs_read`.
  R45 P2-1 made wrap-key source implicit: the fs handle retains
  `keyfile_path` / `janus_socket` strdup'd at mount, and the
  create call reuses the SAME source per-call (load → use → wipe).
  Per-call overrides have no documented use case (ARCH §7.7
  defines wrap keys as pool-wide), and accepting one would let a
  caller silently persist an unwrappable CURRENT entry that R42
  P1-1's hard-fail-on-CURRENT-unwrap-failure would turn into a
  permanent mount refusal — the substantive commit's
  `stm_fs_create_dataset_opts` was removed in the R-close pass to
  close that footgun by construction. Atomicity: on
  `stm_sync_add_dataset_key` failure the freshly-created leaf is
  rolled back via `stm_dataset_destroy` (infallible-by-spec for a
  non-root no-children leaf under fs->lock). No format break, no
  spec change. test_fs 31 → 40 (9 net new tests). R45 audit:
  0 P0 + 0 P1 + 1 P2 + 4 P3 — P2-1 + P3-1 (docstring drift) +
  P3-2 (dead defensive wedge) + P3-4 (test gaps: name-length +
  multi-call sequencing) all fixed inline; P3-3 (next_id burn on
  STM_ERANGE rollback) cosmetic at any realistic scale, deferred.**
  Prior: P7-12 truncate fault-free Phase 3 `5eba5de` +
  R44 close `bb5e088` + hash fixup `31ace1c`.
  **P7-12 truncate fault-free Phase 3 — closes R41 P3-1 case (b)
  (the one gap left open by P7-11). Adds `stm_extent_truncate_peek`
  (pure-read count of past-extents + total replicas) and
  `stm_extent_truncate_into` (truncate using caller-provided
  pre-allocated buffers; never allocates internally). `stm_sync_
  truncate` now peek-counts past-extents and pre-allocates Phase 3
  buffers BEFORE Phase 2's overwrite — any ENOMEM surfaces with
  the index unchanged. Phase 3's `_into` cannot fail with ENOMEM;
  composed with P7-11's single-lock-span, the whole truncate is
  atomic w.r.t. concurrent commit/write AND ENOMEM-safe. No format
  break, no spec change. test_extent_index 51 → 55. R44 audit:
  0 P0 + 0 P1 + 0 P2 + 4 P3 — green signal; P3-1 SPEC-TO-CODE
  refinement rows + P3-2 misleading comment + P3-4 zero-before-
  validate convention all fixed inline; P3-3 end-to-end
  ENOMEM-injection test continues R43 P3-2's deferral (needs
  malloc-failure harness, not in v2's test infra yet).**
  Prior: P7-11 truncate _locked atomicity refactor `0a59ab2` +
  R43 close `9af916e` + hash fixup `d874a04`.
  **P7-11 truncate _locked atomicity refactor — `stm_sync_truncate`
  now holds `sync->lock` across all three phases (lookup → read+
  re-encrypt → past-extent drop + drop-route) under one acquisition.
  Closes **R41 P3-1 case (a)** (concurrent `stm_sync_commit` between
  Phase 2 and Phase 3 splits the on-disk view) and **R41 P3-2**
  (scrub-flavored variant). The R41 P3-1 case (b) (Phase 3
  `stm_extent_truncate` STM_ENOMEM after Phase 2 succeeded → partial
  in-RAM state committable by next sync_commit) is **NOT** closed by
  this chunk and remains documented as a deferred POSIX-atomicity
  gap. Refactors `stm_sync_write_extent` / `stm_sync_read_extent`
  into thin public-wrapper + internal `_locked` variant pairs;
  Phase 2 of truncate uses the `_locked` variants under the outer
  lock-hold. Lock-graph unchanged: `sync.lock` OUTER → `extent_idx.lock`
  + per-device `alloc.lock` INNER. No format break, no spec change.
  Trade-off: lock-hold extends across decrypt + encrypt + bdev I/O
  for the crossing extent's prefix; cascades scrub-step latency
  through the verify cb's brief s->lock takes. R43 audit: 0 P0 +
  0 P1 + 0 P2 + 4 P3 — P3-1 (case-(b) docstring overreach) +
  P3-3 (scrub-step throughput cascade) fixed inline via docstring
  honesty pass; P3-2 (regression test for case (b)) deferred until
  the case-(b) fix lands; P3-4 (pre-existing pool.rdlock omission
  on _write/_read_extent_locked's bdev access) explicitly out of
  scope for R43, surfaced for future-chunk pickup.**
  Prior: `394150a` (**P7-10 per-dataset DEKs** — every extent
  now carries a `key_id` field naming which DEK in the dataset's
  keyschema decrypts it; sync resolves DEK by `(dataset_id, key_id)`
  instead of using `metadata_key`. `stm_sync_create` auto-installs
  the root dataset's DEK at format time alongside the pool metadata
  key. Production scrub β cb + send/recv pick the DEK by the
  extent's stamped `key_id` — RETIRED keys remain reachable so
  pre-rotation extents stay decryptable. `stm_sync_keyschema_sweep`
  refuses to prune any RETIRED key with live extent references
  (closes the long-standing P4-4c TODO; maps to
  key_schema.tla::PruneSafety). Format break STM_UB_VERSION
  14 → 15: extent on-disk value's offset-56 slot — the always-zero
  `xxh` field in v13/v14 — is repurposed for `key_id` (le64).
  Spec extension: `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`;
  Write/Overwrite/Truncate stamp it. extent.cfg holds `MaxKeyIds=1`
  to preserve the P7-9 partial-shrink coverage at 838164 states;
  new `extent_keyids.cfg` runs MaxKeyIds=2 at the pre-P7-9 bound
  (67304 distinct states; 5s wall) so spanning-rotation scenarios
  exist in TLC.
  Prior: P7-9 truncate partial-extent split `5530a0e`
  (`stm_sync_truncate` shrinks crossing extent under fresh
  `(paddr_0, current_gen)` nonce). P7-8 snap-gen alignment
  `73019c4` (UB v13 → v14, `extent_txg` field). P7-7 send/recv
  MVP `1122d32`. P7-6 replica-list extension `a958af6` (UB v12
  → v13). Phase 5 tagged `phase-5-complete` at `461e68e`.
  Spec posture: **21 modules / 25 fixed configs / 31 buggy demos**
  (P7-CAS adds `cas.tla` + `cas.cfg` + 6 cas_*_buggy.cfg variants;
  prior P7-16 added `reflink_rotates_origin_buggy.cfg`; the prior
  `extent_keyids.cfg` fixed cfg is unchanged).
- **Phases**: 1–5 complete; Phase 6 namespace layer feature-
  complete; **Phase 7 progressing**.
  Spec scaffolds: P6-1 (bptr.tla) `032db86`; P6-2 (dataset.tla)
  `75f6a3f`; P6-3 (snapshot.tla) `8813027`; P6-4 (property.tla)
  `2b6f248`; P6-5 (clone.tla) `3db8b5e`; P6-6 (dead_list.tla)
  `d568ff7`. C impls: P6-2 dataset `6dbf8f0` + R28 `bdb888b`;
  P6-3 snapshot `34d89f5` + R29 `000d394`; P6-4 property `3527fe2`
  + R30 `8be3628`; P6-persist `348d165` + R31 `bffee62`; P6-clone
  `ee45a0d` + R32 `4503405`; P6-deadlist C impl
  `18b9289` + R33 `d4efeeb`. P6-perf bench `d4c6708`.
  Phase 7 entry: P7-1 spec scaffold (extent.tla) `4eace52`.
  P7-2 extent C impl `732b20e` + R34 close `433d2dd`.
  P7-3 extent persistence `b223975` (R35 audit clean).
  P7-4 fs.c/sync.c COW integration `bb2d666` + R36 close
  `64a6278` — POSIX-shape stm_fs_write / stm_fs_read;
  sync_drop_paddr_locked composes extent.tla::Overwrite +
  dead_list.tla::OverwriteBlock + allocator.tla::Free;
  advance_txg per sync_commit (R35 forward note acted on).
  P7-5 production scrub cb `38e6799` + R37 close `fc5f619` —
  paddr→bptr resolver; AEAD-verify; mapped to bptr.tla's
  NReplicas=1 corner.
  **P7-6 replica-list extension `2eb898d` + R38 close
  `8d0c172` (this commit) — extent record value layout grows
  32B → 64B with up to 4 replica paddr slots (P7-6 / v13).
  `stm_sync_write_extent` reserves N=mirror_n replicas across
  N distinct devices, encrypts ONCE under (replicas[0], gen) and
  copies bytewise-identical ciphertext+tag to every replica.
  `stm_sync_read_extent` walks replicas (first AEAD-OK wins).
  `sync_scrub_verify_cb` realizes bptr.tla's full ScanRead ×
  RewriteReplica matrix: per-replica csum-gate, pick first OK
  source, rewrite non-OK replicas, verify writeback.
  STM_UB_VERSION 12 → 13. Spec extension: extent.tla gains
  `replicas` field, `MaxReplicasPerExtent` constant, and
  `LiveReplicasDisjoint` + `ReplicasNonEmpty` +
  `ReplicaCountBounded` invariants; new buggy demo
  `extent_replica_collision_buggy.cfg`**.
  P7-7 send/recv MVP `a42d84d` + R39 close `73e9f20`
  — new `src/send_recv/` module. Wire format: framed records (16B
  framing + body); HEADER once, EXTENT* with plaintext payload,
  END with BLAKE3 csum over prior bytes. Send decrypts source's
  extents under source pool's metadata_key; recv re-encrypts
  under target's. Single-dataset full-send only at MVP; the
  incremental send was API-wired but with a best-effort filter.
  **P7-9 truncate partial-extent split `ad95a5d` + R41 close
  `5530a0e` (this commit) — closes the long-standing MVP gap
  where `stm_extent_truncate` dropped only fully-past-truncation
  extents, leaving any crossing extent at original full length
  with a stale AEAD-tag-failing read on bytes past `new_size`.
  New `stm_sync_truncate(s, ds, ino, new_size)` reads + decrypts
  the crossing extent's full plaintext, re-encrypts the kept
  `[0, new_size - off)` prefix under FRESH `(paddr_0,
  current_gen)` AEAD nonce via `stm_sync_write_extent`'s overwrite
  path (which drops + drop-routes the original's replicas
  through dead-list / free per the COW pattern), then drops every
  extent past `new_size` via `stm_extent_truncate` + per-paddr
  `sync_drop_paddr_locked`. Spec refinement in
  `extent.tla::Truncate`: branch (a) keeps the existing drop-
  only behavior when no extent crosses; branch (b) replaces the
  single crossing extent (NoOverlapWithinIno guarantees ≤ 1)
  with a shrunk extent at the same off, len = `new_size - off`,
  fresh replicas disjoint from `used_paddrs`, gen = `current_txg`.
  Re-encrypting under fresh paddrs prevents `(paddr, gen)` reuse
  that would otherwise share a nonce between the original full
  ciphertext and the new shrunk-prefix's plaintext. No format
  break. test_fs grows 20 → 26 (6 new tests: crossing-shrink,
  boundary no-op, truncate-to-zero, past-EOF no-op, snapshot
  dead-list routing, args validation). 33 ctest suites green
  default + ASan + TSan in isolated runs. R41 audit:
  0 P0 + 0 P1 + 0 P2 + 5 P3 — P3-3 strict dead-list count + P3-4
  TLC bound bump + P3-5 rec.len defense check fixed inline;
  P3-1/P3-2 documented as known atomicity gaps (deferred to a
  future _locked refactor of write_extent / read_extent).**
  P7-8 snap-gen alignment `4f40743` + R40 close `c9c29ee`
  — closes the P7-7 incremental gap. New 8-byte
  `extent_txg` field on every snapshot entry, captured from
  `sync.current_gen` at SnapshotCreate. Send filters by
  `extent_txg` (same counter space as `extent.gen`) — filter is
  now authoritative when callers follow the documented bracketed
  pattern `commit → snap_create → commit`. Format break v13 → v14
  (snapshot record value layout: SP_VAL_FIXED 44 → 52 with the
  new field at offset 24..32). Spec change: new variable
  `sync_gen` distinct from `current_txg`; `Write` bumps `sync_gen`
  only; `SnapshotCreate` captures `sync_gen` as `snap_extent_txg`;
  invariants `ExtentTxgBoundedBySync` + `ChainExtentTxgOrdered`;
  buggy variant `BuggyExtentTxgUnbounded` + companion config.
  C surface: `stm_snapshot_entry` gains `extent_txg` field;
  `stm_snapshot_create` signature gains `extent_txg` arg + R40
  P2-1 chain-ordering validation under idx->lock; structural
  validator extended; new accessor `stm_sync_current_gen`. R40
  audit: 0 P0 + 0 P1 + 1 P2 + 6 P3 (P2-1 + P3-1/2/4/5/7 fixed
  inline; P3-3 + P3-6 deferred per audit close commit).
  **P7-10 per-dataset DEKs `a3610f2` + R42 close `394150a`
  (this commit) — every extent
  now carries a `key_id` field naming which DEK in the dataset's
  keyschema decrypts it; sync layer resolves DEK by
  `(dataset_id, key_id)` instead of using the per-pool
  `metadata_key`. `stm_sync_create` auto-installs the root
  dataset's DEK as keyschema entry `(1, 0, CURRENT)` alongside
  the pool metadata key `(0, 0)`; non-root datasets continue to
  use `stm_sync_add_dataset_key`. The production scrub β cb and
  send/recv resolve DEK by the extent's stamped `key_id` —
  RETIRED keys remain reachable so pre-rotation extents stay
  decryptable. `stm_sync_keyschema_sweep` walks the extent index
  and refuses to prune any RETIRED key with live extent
  references (closes the long-standing P4-4c TODO; maps to
  key_schema.tla::PruneSafety; the operator can sweep again after
  extents migrate via overwrite / re-encrypt sweep). Format break
  STM_UB_VERSION 14 → 15: extent on-disk value's offset-56 slot
  (the always-zero `xxh` field in v13/v14) is repurposed for
  `key_id` (le64); EX_VAL_LEN stays 64. v14 pools fail at
  uberblock version check before the value layer is reached.
  Spec extension: `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`;
  `Write/Overwrite/Truncate` stamp it. `extent.cfg` holds
  `MaxKeyIds=1` to preserve the P7-9 partial-shrink coverage at
  838164 states; new `extent_keyids.cfg` runs MaxKeyIds=2 at the
  pre-P7-9 bound (67304 distinct states; 5s wall) so
  spanning-rotation scenarios — distinct extents under distinct
  key_ids — are realized in TLC. R42 audit:
  0 P0 + 1 P1 + 2 P2 + 5 P3 — P1-1 mount-fail on tampered CURRENT
  + P2-1 send DEK snapshot at init + scrub race-tolerant OK +
  P2-2 wedged/RO guards on sweep/add/rotate + P3-1 spec invariant
  comment + P3-3 super.h docstring + P3-4 helper docstring fixed
  inline; P3-2 docs-with-substantive-commit + P3-5 extent_full.cfg
  deferred per project conventions.**
  Phase 7 pre-work FastCDC `5cb8900` + R27 close `a2ffd38`.
  Pending: CAS / reflinks (Phase 7 §10.1, §10.4);
  repair log persistence; truncate `_locked` atomicity refactor.
- **Tests**: 33 suites × (default + ASan + TSan, serial) green
  (P7-10 grows test_fs 26 → 31 with four new per-dataset DEK
  tests + R42 P2-2 wedged/RO refuse test; test_keyschema_rotate
  15 → 17 with two new root-DEK tests).
  test_sync_multi 42; test_pool 48; test_scrub 34 (30 + 4 P7-6
  replica-walk); test_alloc 32; test_cdc 12; test_dataset 57;
  test_snapshot 41; test_sync 24;
  test_extent_index 51 (32 in-RAM + 6 persist + 4 lookup_by_paddr +
  9 P7-6 multi-replica); test_fs 31 (P7-10: 4 per-dataset DEK
  tests covering rotation-roundtrip, sweep-refuses-with-refs,
  sweep-after-overwrite-drops-ref, unprovisioned-ds-refused;
  R42 P2-2: keyschema-mutators-refuse-on-RO);
  test_send_recv 13 (4 arg validation + 1 full-send roundtrip +
  1 incremental + 1 swap-rejection + 1 equal-extent_txg + 5
  wire/state-machine error paths).
- **Specs**: 20 TLA+ modules clean (23 fixed configs: legacy +
  scrub_beta + scrub_durable + scrub_beta_durable + bptr +
  dataset + snapshot + property + clone + dead_list + extent) +
  24 buggy-demo configs fire as expected
  (snapshot_extent_txg_unbounded_buggy added in P7-8).
- **LOC**: ~32 KLOC across 24 src/ modules (extent module gains
  `extent_index.c` alongside the Phase 4 `extent.c` AEAD wrapper)
  + 28 public headers.

For phase-level status see `v2/docs/phase{2,3,4,5}-status.md`. The
reference below covers the as-built layers in bottom-up order.

## Contents

| File | Layer | Size guide |
|---|---|---|
| [00-overview.md](reference/00-overview.md) | Layer cake + cross-cutting concerns | medium |
| [01-crypto.md](reference/01-crypto.md) | AEAD, KDF, BLAKE3, PQ-hybrid wrap | large |
| [02-block.md](reference/02-block.md) | stm_bdev backends + fault injection | medium |
| [03-btree.md](reference/03-btree.md) | Single-threaded + rwlock + Bw-tree lock-free | large |
| [04-ebr.md](reference/04-ebr.md) | Epoch-based reclamation | small |
| [05-bootstrap-alloc.md](reference/05-bootstrap-alloc.md) | Two-region allocator | large |
| [06-keyschema.md](reference/06-keyschema.md) | Per-dataset key state machine | medium |
| [07-sb-sync.md](reference/07-sb-sync.md) | Uberblock layout + multi-device commit | large |
| [08-pool-redundancy.md](reference/08-pool-redundancy.md) | Roster + mirror + device lifecycle | large |
| [09-scrub.md](reference/09-scrub.md) | Verify-only sweep + state machine | medium |
| [10-specs.md](reference/10-specs.md) | TLA+ spec catalog + SPEC-TO-CODE dictionary | medium |
| [11-glossary.md](reference/11-glossary.md) | Terms, acronyms, invariant names | small |
| [12-dataset.md](reference/12-dataset.md) | Dataset hierarchy + properties + clones | large |
| [13-snapshot.md](reference/13-snapshot.md) | Snapshot index + clone-check hook | medium |
| [14-extent.md](reference/14-extent.md) | Extent index (P7-2 MVP + P7-3 persistence + P7-4 fs/sync COW path) | medium |

This is a live document — every phase-chunk commit that touches a
subsystem updates the corresponding section in the same PR.

## Document maintenance

When a chunk lands (bug fix, refactor, new module), the author is
responsible for:

1. Updating the relevant reference/NN-*.md section(s).
2. Checking the [Snapshot](#snapshot) figures (tip / phase / test /
   spec counts) still match reality.
3. If the chunk introduces or refutes an invariant, updating
   `10-specs.md`'s SPEC-TO-CODE table.
4. If a new term or acronym enters the lexicon, updating
   `11-glossary.md`.

Reference sections are PR-first like any code change; the audit
policy in `CLAUDE.md` ("spec-first for load-bearing invariants")
extends here: a change to a documented invariant updates the spec
FIRST, then the reference, then the code. If the three disagree,
the spec wins.
