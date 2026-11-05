# 32 — The decrypted-extent cache + the crypto throughput baseline

As-built reference for Stratum's **#343 decrypted-extent cache** (the read-path
plaintext cache that turns a re-read into a memcpy) and the **crypto/integrity
throughput baseline** that measures the one accepted bandwidth delta versus a
mature COW FS. Written for **Stratum Stabilization Area E** (crypto/integrity
throughput — the accepted-delta baseline). Companion to `27-fs-read-path.md`
(the read path the cache sits inside) and `07-sb-sync.md` (the `stm_sync` state
the cache lives in).

---

## 32.1 Purpose

A file read decrypts the **whole** covering extent — AEAD verifies the entire
ciphertext, so even an 8 KiB slice of a 1 MiB extent pays a 1 MiB decrypt
(`27-fs-read-path.md`). REVENANT demand-paged exec faults a large binary's text
in page-sized slices, so without a cache the same extent is re-decrypted once
per fault — read amplification ≈ `extent_size / page_size`. The dcache holds the
decrypted plaintext keyed by the extent's **immutable identity**, so repeated
reads of one extent decrypt it **once**; every subsequent slice is a memcpy.

The cache is **invalidation-free**: an extent's identity is the same pair its
AEAD nonce is derived from, so a key can never name two different live
plaintexts (32.4). There is no invalidation pass to get wrong — a
copy-on-write overwrite simply mints a new identity, and the stale entry is
never looked up again.

---

## 32.2 Data structures — `src/sync/sync.c` (RC-1 as-built)

> **History.** Born 16 entries / 64 MiB, fixed-array, all-under-`s->lock`
> (Area E). CF-5a resized it (2048 entries / 128 MiB), added the chained-hash
> lookup, and made the WRITE path populate it. **RC-1** (the RC arc,
> `docs/rc-design.md` §4; modeled by `specs/dcache_ebr.tla`) reworked it onto
> **EBR-pinned lock-free readers** — the first stage of retiring `s->lock`
> from the extent data path. This section describes the RC-1 shape.

```c
#define STM_DCACHE_ENTRIES      2048u
#define STM_DCACHE_HASH_BUCKETS 4096u                   /* 2x entries; power of 2 */
#define STM_DCACHE_BYTES_MAX    (128u * 1024u * 1024u)  /* 128 MiB ceiling */

struct sync_dcache_entry {
    uint8_t  key[STM_CAS_HASH_LEN];   /* COLD: content_hash; HOT: paddr0||gen||0 */
    uint8_t  kind_tag;                /* STM_EXTENT_KIND_* — disambiguates key space */
    size_t   len;
    _Atomic uint64_t lru_tick;        /* advisory LRU; relaxed */
    struct sync_dcache_entry *_Atomic hnext;  /* bucket chain; NULL == end */
    uint8_t  plaintext[];             /* len bytes tail-allocated */
};
```

Entries are **heap-allocated, immutable once linked** (identity + payload
fields; `lru_tick` is advisory atomic metadata, `hnext` is chain plumbing
mutated only under the writer lock), allocated **fresh per insert** — never
rewritten in place, so a reader that matched an entry's key can never copy a
different key's bytes (the slot-reuse ABA is designed out structurally). The
`stm_sync` side holds:

- `dcache_hash[4096]` — `_Atomic` entry-pointer bucket heads (the lock-free
  readers' entry point);
- `dcache_slots[2048]` — the **writer's** bookkeeping index (free-slot + LRU
  victim scans; readers never touch it);
- `dcache_wlock` — the writer mutex: insert / evict / drain serialize among
  **themselves only**; `s->lock` is not part of the cache's contract. Lock
  order: `s->lock → dcache_wlock`; the cache functions never take `s->lock`;
- `dcache_tick` / `dcache_bytes` / `dcache_hits` / `dcache_misses` — atomics.
  `dcache_bytes` counts **linked** bytes: an evicted entry's bytes leave the
  budget at unlink, transiently before its EBR grace expires.

**Key canonicalization.** Both extent kinds reduce to a 32-byte key + a kind
tag, so one cache and one key space serve HOT, COLD, and snap-view reads:

- **COLD** (content-addressed, the CAS tier): the key is the extent record's
  `content_hash`. A `_Static_assert(STM_EXTENT_HASH_LEN == STM_CAS_HASH_LEN)`
  (`sync.c:162`) pins the two 32-byte widths equal — the COLD key copies
  `content_hash` (an `STM_EXTENT_HASH_LEN` field) into / compares it against an
  `STM_CAS_HASH_LEN`-wide slot, so a future divergence is a build error, not a
  silent OOB read on the memcmp.
- **HOT** (paddr-addressed): the key is `paddrs[0] (8 LE) || gen (8 LE) || 0
  (16)`, built by `dcache_key_hot` (`sync.c:5709`). This is exactly the pair the
  AEAD nonce is built from (32.4).

---

## 32.3 The read-path integration — probe + fetch (RC-2 as-built)

The RC-2 restructure split the pre-RC decrypt body into
`sync_slice_bounds` (pure slice math) + `sync_dcache_probe_pinned` (the
pure probe — computes the arm key, calls `dcache_lookup_copy`; NO pin
management inside) + `sync_extent_fetch_decrypt` (the miss body: CAS
lookup / DEK resolve / bdev read / AEAD decrypt / `dcache_insert`).
The probe is reached from two shapes:

- **The lock-free read paths** (`stm_sync_read_extent` + the snap read):
  ONE `stm_ebr_enter` covers the `_concurrent` extent lookup AND the
  probe — the RC-1 forward note's hoist, realized (nested enter is NOT
  supported; the inner pairs were removed, never nested). The bucket walk
  **and the plaintext memcpy both run under the pin**; no pointer into
  the cache escapes it. The miss fetch runs UNPINNED (a pin must never
  span the blocking bdev read).
- **The under-lock compounds** (truncate / migrate / snap-view / send via
  `sync_decrypt_extent_record_locked`): the RC-1 protocol verbatim —
  resolve the thread's EBR handle (`stm_ebr_thread_current()`; a NULL —
  registration OOM — degrades to a plain miss), enter, probe, exit, then
  the shared fetch with the borrowed under-lock DEK walk.

**COLD branch:** the probe keyed by `rec.content_hash` sits before the CAS
lookup + AEAD decrypt; on a miss, decrypt as before, then
`dcache_insert(...content_hash, COLD, cpbuf, rec.len)` caches the whole
plaintext before the scratch is zeroed + freed.

**HOT branch:** identical shape with the `(paddrs[0], gen)` key. The probe
sits before the DEK resolution + AEAD decrypt; the insert sits after, before
`pbuf` is zeroed + freed.

**The writer protocol:** `dcache_insert` self-serializes on `dcache_wlock`.
It first DEDUPS (at RC-2 two readers can miss one key concurrently and both
arrive post-decrypt; the loser drops its copy — a key names exactly one
plaintext, so either copy is byte-identical), then finds a free slot,
evicting LRU victims while over the slot or byte budget. An evict UNLINKS the
victim from its bucket (the victim's own `hnext` stays intact so pinned
in-flight walkers keep a valid chain), THEN `stm_ebr_retire`s it; the
destructor (memzero + free) runs only once every covering epoch pin has
exited. A fresh entry is fully initialized and only then linked (a release
store of the bucket head — the publish). `dcache_drain` (close, evict-dek,
the test hook) clears every bucket head first, then retires every entry —
same unlink-before-retire discipline; a reader arriving after the drain's
stores finds empty buckets (the evict-dek fail-closed contract, CF-5a F1).
Reclamation is driven by `stm_ebr_try_advance()` from the retire-bearing
paths.

The slice arithmetic is unchanged from `27-fs-read-path.md`: `slice_off = off −
rec.off` (guarded `slice_off < rec.len`, else `out_read = 0`), `slice_len =
min(len, rec.len − slice_off)`. Because the cached entry holds the **whole**
`rec.len`-byte plaintext, `hit + slice_off` reads within `[0, rec.len)` and
`slice_off + slice_len ≤ rec.len` (32.4).

**The provisional insert (RC-6, #35 — the F1 exact-denial close):** the HOT
read-fetch populate births its entry probe-INVISIBLE (`sync_dcache_entry.
visible`, a monotonic 0→1 atomic the lock-free probe skips before the key
memcmp; a stale-clear read is a spurious MISS — refetch — never a wrong
serve) and commits-or-kills it via `dcache_publish_hot_gated`: under ONE
`dcache_wlock` hold, re-check `(dataset_id, key_id)` liveness in the DEK map
(`sync_dek_slot_alive`; a short own EBR pin on the lock-free path, the
borrowed s->lock walk on locked-context fetches), then flip the `(key, HOT)`
entry visible (release store, paired with the probe's acquire) or remove it
(`dcache_remove_key_locked`, the kill arm). Key-addressed, not
pointer-addressed: an entry evicted/drained in the window is simply not
found (fail-closed), and a dedup twin is byte-identical (I-dcache-1). The
liveness re-check runs UNDER the flipping wlock hold — the load-bearing
piece: a flip ordered after `stm_sync_evict_dek`'s drain observes the slot
removal via mutex happens-before and takes the kill arm; a flip ordered
before the drain (including one whose lock-free map read was stale-alive in
the `dek_remove..drain` window) is wiped by the drain before evict returns.
The split check-then-flip design is the modeled near-miss
(`specs/dcache_provisional.tla::stale_publish` — a stale publish flips
ANOTHER populator's post-drain provisional insert visible after evict
returned). Visible-at-birth stays for the write-populate (its epilogue holds
`s->lock`, which the whole evict also holds — the pre-gate is atomic with
the insert), COLD (pool-wide `metadata_key`, no DEK dependency), and the
test shim. A late publish that finds the slot REINSTALLED flips legitimately
(the entry decrypted under the same key material the reinstall restored —
equivalent to a fresh fetch); the denial contract binds the evicted state,
not the reinstalled one.

---

## 32.4 Invariants

**I-dcache-1 — no stale plaintext is ever served.** The key is injective on
*live* plaintexts:

- HOT: `(paddrs[0], gen)` is the AEAD-nonce identity. Stratum is copy-on-write
  with a strictly-monotonic per-commit `gen`, so an overwrite writes a **new**
  `(paddr|gen)`, and a freed paddr is reused only at a strictly-greater `gen`.
  Two distinct live plaintexts therefore never share a key (a shared key would
  also be a reused AEAD nonce, which the FS forbids). A CoW leaves the old
  entry resident-but-**unreferenced** — its key is never looked up again, so it
  is never served; it ages out via LRU or is freed at drain.
- COLD: the key is `content_hash`, content-addressed — identical content has
  identical plaintext, so a shared COLD entry across two references (even
  cross-dataset, since CAS is pool-wide) serves the *correct* bytes by
  construction.

The `kind_tag` partitions the two key spaces, so a HOT key
(`paddr||gen||zeros`) can never alias a COLD `content_hash`. The `len` is part
of the lookup match (`sync.c:5722`); since a `content_hash` / `(paddr,gen)` has
exactly one length, the len-match is belt-and-suspenders, not load-bearing.

**I-dcache-2 — memory safety (RC-1: concurrent).** `slice_off < rec.len ==
e->len` (the lookup matches `e->len == rec.len`) and `slice_off + slice_len ≤
rec.len` (defensively re-checked inside `dcache_lookup_copy`), so the slice
memcpy is in-bounds. The copy runs under the reader's **EBR pin**: an entry
reachable from a bucket chain cannot be reclaimed until every covering pin
exits, so a concurrent evict/drain retires — never frees — the buffer under
the copy. This is `specs/dcache_ebr.tla::NoUseAfterReclaim`; the buggy cfg
`evict_frees_pinned` is the immediate-free counterexample.

**I-dcache-3 — no secret leak.** Cached plaintext is `stm_ct_memzero`'d
before `free` in the EBR destructor (`dcache_entry_destroy`) on every release
path — evict, drain, close (where `stm_sync_close` additionally runs
`stm_ebr_drain()` so a final close reclaims rather than stranding retires
until process exit). A retire-record OOM leaks the entry rather than freeing
under a possibly-pinned reader (the engine's posture); it is already
unlinked, so it can never be observed again.

**I-dcache-4 — concurrency discipline (RC-1; replaces the retired
"every accessor under `s->lock`" contract).** Readers are lock-free: pin →
acquire-load the bucket head → walk → copy → unpin. Writers (insert / evict /
drain) serialize on `dcache_wlock` and never take `s->lock`. Publish order is
init-everything-THEN-link (`LinkedImpliesInit` / `NoTornEntry`; buggy cfg
`link_before_init`); removal order is unlink-THEN-retire
(`LinkedNeverReclaimed`; buggy cfg `retire_still_linked`); an unlinked
victim's `hnext` stays intact for in-flight walkers. The model is
`specs/dcache_ebr.tla` (clean cfg green incl. the `EventuallyReclaimed`
liveness witness); the runtime witness is
`tests/test_dcache_concurrent.c::dcache_concurrent_hammer` (pinned readers
byte-verify every hit against a key-derived pattern while a writer
insert/evict/drain-churns past the byte budget).

**I-dcache-5 — bounded + terminating.** `dcache_insert` caps a single entry
at `STM_DCACHE_BYTES_MAX` and evicts the LRU entry until the new plaintext
fits. The eviction loop terminates in ≤ `STM_DCACHE_ENTRIES` iterations (each
pass unlinks one entry + reduces linked bytes; once empty, `0 + len ≤ MAX` is
guaranteed by the entry guard). `dcache_bytes` is the exact sum of **linked**
`len`s and cannot underflow (eviction subtracts a summand); retired-but-not-
yet-reclaimed buffers transiently sit outside the budget, bounded by the EBR
grace (`stm_ebr_try_advance` is driven from every insert). The linked
plaintext is bounded by `min(2048 entries, 128 MiB)`. A provisional entry
(RC-6) occupies its slot + budget bytes while invisible — bounded by the
same caps, evictable by the same LRU (the publish tolerates the entry
vanishing), and never left provisional by any production path (the publish
is straight-line after the insert; a dedup-dropped copy leaves the flip to
the twin's own key-addressed publish).

**I-dcache-6 — no post-logout serve (RC-6; the CF-5a F1 contract, exact).**
Once `stm_sync_evict_dek` returns, no HOT entry under that dataset's key is
probe-servable — for EVERY party, including a third reader racing an
in-flight fetch populate. Pinned by `specs/dcache_provisional.tla`
(`NoVisiblePostEvict` + `NoStuckProvisional`; buggy cfgs `visible_birth` =
the pre-RC-6 three-party trace, `stale_publish` = the four-party
split-publish trace). Runtime witnesses:
`tests/test_corvus_mount.c::corvus_rc6_read_evict_third_party` (the
deterministic F1 witness via the `read_postinsert` seam; revert-probed),
`corvus_rc6_read_populate_publish` (the anti-silent-regression publish pin;
revert-probed), `corvus_rc6_readers_vs_evict_hammer` (4 readers vs 40
evict/install cycles, odd/even phase stamp).

---

## 32.5 Observability

`dcache_hits` / `dcache_misses` are **always-on** (relaxed-atomic bumps in
`dcache_account`). The supported read path is
`stm_sync_dcache_stats(s, &hits, &misses, &cached_bytes)` (`sync.h`) — an
atomic-snapshot triple, any out-param NULL-able, suitable for a `/ctl/metrics`
probe or a test. A periodic `STRATUM-DCACHE: hits=… misses=… cached_bytes=…`
stderr line is a **compile-time dev convenience** behind `-DSTM_DCACHE_STATS`
(default off — it never spews on the production read path).

---

## 32.6 The crypto/integrity throughput baseline (`tests/bench_crypto.c`)

Area E's measurement reference: the cryptographic layer is the **one accepted
bandwidth delta** versus a mature COW FS, so every other area's throughput is
judged against these numbers. Stratum has **no plaintext FS mode**
(`stm_fs_format_opts` requires a keyfile), so the "with/without AEAD" isolation
the charter mandates is done at the **primitive** level here, not by an FS
toggle. Representative numbers (Apple M2, `STM_BENCH_MIB=256`; absolute MB/s is
host-CPU-bound, the *ratios* are the portable signal):

| Layer | 4 KiB | 64 KiB | 1 MiB | 8 MiB |
|---|---|---|---|---|
| **AEGIS-256** enc (production cipher, AES-accel) | 5073 | 8827 | 8835 | 8843 |
| **AEGIS-256** dec | 6096 | 7751 | 7897 | 7824 |
| **XChaCha20-SIV** enc (fallback, no-AES) | 199 | 209 | 210 | 203 |
| **XChaCha20-SIV** dec | 193 | 208 | 209 | 203 |
| **BLAKE3-256** (Merkle / CAS hash, NEON) | 1808 | 1888 | 1898 | 1907 |
| **xxHash3-64** (unencrypted-volume csum) | 38033 | 36766 | 38531 | 38427 |

(all MiB/s).

**The headline G2 result.** On the production cipher (AEGIS-256, picked by
`stm_aead_autodetect` on any AES-accelerated CPU — Thylacine's ARM64 target has
the crypto extensions), the AEAD layer runs at **~7.6 GiB/s decrypt / ~8.6 GiB/s
encrypt** — *far* above any single-NVMe bandwidth (~1–7 GB/s). The crypto layer
is **not** the bottleneck for sequential I/O on the target hardware; the
"accepted delta" is small. Integrity hashing is near-parity (BTRFS/ZFS checksum
too) — xxHash3 at ~37 GiB/s is far above any device, and BLAKE3 at ~1.9 GiB/s
(NEON, enabled in Area E — 32.8) is comfortably above NVMe.

**The dcache benefit** (`bench_crypto`'s last row): a 1 MiB extent re-read is
a `decrypt → memcpy` swap — **~7.6 GiB/s decrypt (miss) → ~65–77 GiB/s memcpy
(hit), an ~8–10× speedup** (the memcpy column is host-cache-sensitive; the
decrypt is stable; the memcpy is timed under a compiler barrier so it is
elision-proof). For REVENANT (a binary's text faulted in many page slices), the
cache eliminates `(N−1)/N` of the decrypt work.

---

## 32.7 Tests

| Test | What it pins |
|---|---|
| `tests/test_fs.c::dcache_hit_serves_same_plaintext` | A re-read HITS (the `hits` counter advances, no second decrypt), serves byte-identical plaintext to the miss, and a **disjoint never-read slice** of the same extent also hits — proving the miss cached the *whole* plaintext. Non-vacuous: a disabled cache fails the hit-delta assert (proven by injection — `dcache_lookup → NULL` makes it FAIL). |
| `tests/test_fs.c::dcache_cow_overwrite_serves_new_plaintext` | THE safety property: after a CoW overwrite (new commit → new `gen`), a re-read of the same offset is a **MISS** on the fresh key and serves the **NEW** bytes, never the stale cached plaintext. Non-vacuous: a gen-blind key (e.g. ino+offset) would hit + serve stale, failing both the miss-stat delta and the content compare. |
| `tests/test_dcache_concurrent.c::dcache_semantics` | RC-1 single-thread contract: pinned lookup returns exact bytes (full + slice); len/kind participate in the match; dedup keeps one copy; drain empties fail-closed and the cache stays serviceable after it. |
| `tests/test_dcache_concurrent.c::dcache_slot_lru_evict` | Slot-cap eviction is strictly LRU (fill past the cap: the oldest keys miss, the newest hit, bytes verify). |
| `tests/test_dcache_concurrent.c::dcache_concurrent_hammer` | THE RC-1 concurrency witness: 4 pinned reader threads slice-verify key-derived patterns (byte-for-byte, zero tolerance) while a writer insert/evict/drain-churns the cache past its byte budget; ~2.3M verified hits per run. A torn entry, wrong-key copy, or freed-buffer read fails the content check. (The Linux TSan run of this hammer is owed to the GCP sanitizer pass — macOS TSan is broken at runtime-init on this host.) |
| `tests/bench_crypto.c` | The throughput measurement reference (a bench, not a ctest). |

---

## 32.8 Known caveats / tracked perf debt

- **BLAKE3 SIMD (NEON) enabled in Area E.** The original wiring compiled only
  `blake3_portable.c` ("re-enable SIMD once benchmarks justify"); the crypto
  bench measured the portable path leaving ~2.3× on the integrity layer (Merkle
  / CAS hashing). `third_party/CMakeLists.txt` now compiles the vendored
  `blake3_neon.c` (NEON is baseline on ARMv8) with `BLAKE3_USE_NEON=1`, ARM-gated
  (x86 stays portable). **~830 → ~1900 MiB/s (2.3×)**, AEAD/tamper vectors still
  passing. BLAKE3 SIMD is bit-for-bit the portable hash, so on-disk Merkle/CAS
  values are unchanged — validated by the full suite passing with NEON (existing
  pools stay valid). A remaining lever: x86 SIMD (SSE/AVX) is still off (no
  on-target need; would want the BLAKE3 runtime-dispatch wiring).
- **The XChaCha20-SIV fallback is ~40× slower than AEGIS-256** (~200 MB/s). It
  is the AEAD only on hardware *without* AES acceleration; the Thylacine ARM64
  target has the crypto extensions, so AEGIS-256 is used. On an AES-less
  substrate the data path would be AEAD-bound at ~200 MB/s — a documented
  fallback characteristic, not a target-hardware regression.
- **The dcache is per-`stm_sync` (per-pool), 2048 entries / 128 MiB linked**
  (CF-5a sizing; the pre-CF-5a 16/64 MiB was slot-bound for a whole-build
  working set). There is no cross-mount sharing (each pool's plaintext stays
  in its own sync). Retired-but-unreclaimed buffers transiently exceed the
  linked budget within an EBR grace (32.4 I-dcache-5).
- **Write-populated since CF-5a**: `stm_sync_write_extent` inserts the
  committed plaintext (the bytes are in hand), so a freshly-written extent's
  first read is a RAM hit. Only the SUCCESS path populates — a failed write
  must not leave never-live bytes servable.
- **LRU metadata is advisory under concurrency** (RC-1): `lru_tick` updates
  are relaxed atomics from lock-free readers; the victim choice is
  best-effort LRU, never a correctness input.

---

## 32.9 Status

Implemented (Area E; resized + write-populated at CF-5a; EBR-pinned lock-free
readers at RC-1 — `docs/rc-design.md` §4, `specs/dcache_ebr.tla`; the
provisional insert + gated publish at RC-6 — `docs/rc-design.md` "RC-6",
`specs/dcache_provisional.tla`): the dcache
(`src/sync/sync.c`), the `stm_sync_dcache_stats` accessor
(`include/stratum/sync.h`), the test hooks (`include/stratum/sync_testing.h`),
the correctness regressions (`tests/test_fs.c`,
`tests/test_dcache_concurrent.c`, the `corvus_rc6_*` trio in
`tests/test_corvus_mount.c`), and the crypto throughput baseline
(`tests/bench_crypto.c`) + the BLAKE3-NEON SIMD enable
(`third_party/CMakeLists.txt`, 2.3× integrity throughput, 32.8). Closed
lists: `memory/audit_stratum_E_closed_list.md` (Area E),
`audit_cf5a_closed_list` (CF-5a, in the Thylacine project memory), the RC-1
focused audit in the RC arc, `audit_rc6_closed_list` (RC-6, in the Thylacine
project memory).
