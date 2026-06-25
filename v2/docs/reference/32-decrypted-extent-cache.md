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

## 32.2 Data structures — `src/sync/sync.c`

```c
#define STM_DCACHE_ENTRIES     16u                     /* sync.c:146 */
#define STM_DCACHE_BYTES_MAX   (64u * 1024u * 1024u)   /* 64 MiB ceiling */

struct sync_dcache_entry {                             /* sync.c:150 */
    uint8_t  key[STM_CAS_HASH_LEN];   /* COLD: content_hash; HOT: paddr0||gen||0 */
    uint8_t  kind_tag;                /* STM_EXTENT_KIND_* — disambiguates key space */
    uint8_t *plaintext;               /* malloc(len); NULL == empty slot */
    size_t   len;
    uint64_t lru_tick;
};
```

The cache is **16 fixed entries** embedded in `struct stm_sync` (`sync.c:174`)
plus four scalars: `dcache_tick` (the LRU clock), `dcache_bytes` (the resident
plaintext total, bounded by the 64 MiB ceiling), and `dcache_hits` /
`dcache_misses` (lifetime counters). All-zero (from the `stm_sync` calloc) is a
valid empty cache — no explicit init.

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

## 32.3 The read-path integration — `sync_decrypt_extent_record_locked`

The cache wraps the per-extent decrypt at the two decrypt sites in
`sync_decrypt_extent_record_locked` (the function the live read +
the snap-view read both funnel through). Caller holds `s->lock`.

**COLD branch (`sync.c:5930`):** before the CAS lookup + AEAD decrypt, probe
`dcache_lookup(s, rec.content_hash, STM_EXTENT_KIND_COLD, rec.len)`. On a hit,
`memcpy(buf, hit + slice_off, slice_len)` and return — no disk read, no decrypt.
On a miss, decrypt as before, then `dcache_insert(...content_hash, COLD, cpbuf,
rec.len)` caches the whole plaintext before the scratch is zeroed + freed.

**HOT branch (`sync.c:6038`):** identical shape with the `(paddrs[0], gen)`
key. The probe sits before the DEK resolution + AEAD decrypt; the insert sits
after, before `pbuf` is zeroed + freed.

The slice arithmetic is unchanged from `27-fs-read-path.md`: `slice_off = off −
rec.off` (guarded `slice_off < rec.len`, else `out_read = 0`), `slice_len =
min(len, rec.len − slice_off)`. Because the cached entry holds the **whole**
`rec.len`-byte plaintext, `hit + slice_off` reads within `[0, rec.len)` and
`slice_off + slice_len ≤ rec.len` (32.4).

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

**I-dcache-2 — memory safety.** `slice_off < rec.len == e->len` (the lookup
matches `e->len == rec.len`) and `slice_off + slice_len ≤ rec.len`, so the slice
memcpy is in-bounds. The returned plaintext pointer is used (memcpy'd) while
`s->lock` is held continuously — no concurrent eviction can free it mid-copy.

**I-dcache-3 — no secret leak.** Cached plaintext is `stm_ct_memzero`'d before
`free` on every release path: eviction (`dcache_insert`, `sync.c:5768`), and
drain (`dcache_drain`, `sync.c:5776`, called from `stm_sync_close` at
`sync.c:2460` before the lock is destroyed). The cache cannot outlive its
`stm_sync`.

**I-dcache-4 — lock discipline.** Every accessor runs under `s->lock`:
`dcache_lookup` / `dcache_insert` / `dcache_account` from the `_locked` decrypt
path; `dcache_drain` at single-threaded close; the public
`stm_sync_dcache_stats` (`sync.c:4961`) takes `s->lock` itself. The stats
accessor is a leaf (takes `s->lock`, reads three scalars, releases) and is
never called from inside the lock, so it cannot self-deadlock.

**I-dcache-5 — bounded + terminating.** `dcache_insert` (`sync.c:5732`) caps a
single entry at `STM_DCACHE_BYTES_MAX` and evicts the LRU entry until the new
plaintext fits. The eviction loop terminates in ≤ `STM_DCACHE_ENTRIES`
iterations (each pass frees one entry + reduces `dcache_bytes`; once empty,
`0 + len ≤ MAX` is guaranteed by the entry guard). `dcache_bytes` is the exact
sum of live `len`s and cannot underflow (eviction subtracts a summand). The
resident plaintext is bounded by `min(16 entries, 64 MiB)`.

---

## 32.5 Observability

`dcache_hits` / `dcache_misses` are **always-on** (cheap counter bumps in
`dcache_account`, `sync.c:5789`). The supported read path is
`stm_sync_dcache_stats(s, &hits, &misses, &cached_bytes)` (`sync.h`) — a
lock-snapshotted triple, any out-param NULL-able, suitable for a `/ctl/metrics`
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
| **BLAKE3-256** (Merkle / CAS hash) | 848 | 819 | 832 | 835 |
| **xxHash3-64** (unencrypted-volume csum) | 38033 | 36766 | 38531 | 38427 |

(all MiB/s).

**The headline G2 result.** On the production cipher (AEGIS-256, picked by
`stm_aead_autodetect` on any AES-accelerated CPU — Thylacine's ARM64 target has
the crypto extensions), the AEAD layer runs at **~7.6 GiB/s decrypt / ~8.6 GiB/s
encrypt** — *far* above any single-NVMe bandwidth (~1–7 GB/s). The crypto layer
is **not** the bottleneck for sequential I/O on the target hardware; the
"accepted delta" is small. Integrity hashing is near-parity (BTRFS/ZFS checksum
too) — xxHash3 at ~37 GiB/s is far above any device, and BLAKE3 is comparable to
portable SHA-256 (with a 2.3× SIMD lever available, 32.8).

**The dcache benefit** (`bench_crypto`'s last row): a 1 MiB extent re-read is
a `decrypt → memcpy` swap — **~7.4 GiB/s decrypt (miss) → ~75 GiB/s memcpy (hit),
a 10.1× speedup** (the memcpy timed under a compiler barrier so the number is
elision-proof). For REVENANT (a binary's text faulted in many page slices), the
cache eliminates `(N−1)/N` of the decrypt work.

---

## 32.7 Tests

| Test | What it pins |
|---|---|
| `tests/test_fs.c::dcache_hit_serves_same_plaintext` | A re-read HITS (the `hits` counter advances, no second decrypt), serves byte-identical plaintext to the miss, and a **disjoint never-read slice** of the same extent also hits — proving the miss cached the *whole* plaintext. Non-vacuous: a disabled cache fails the hit-delta assert (proven by injection — `dcache_lookup → NULL` makes it FAIL). |
| `tests/test_fs.c::dcache_cow_overwrite_serves_new_plaintext` | THE safety property: after a CoW overwrite (new commit → new `gen`), a re-read of the same offset is a **MISS** on the fresh key and serves the **NEW** bytes, never the stale cached plaintext. Non-vacuous: a gen-blind key (e.g. ino+offset) would hit + serve stale, failing both the miss-stat delta and the content compare. |
| `tests/bench_crypto.c` | The throughput measurement reference (a bench, not a ctest). |

---

## 32.8 Known caveats / tracked perf debt

- **BLAKE3 runs the portable (non-SIMD) path** — `third_party/CMakeLists.txt`
  compiles only `blake3_portable.c` ("re-enable SIMD in Phase 9 once benchmarks
  justify"). Area E is that benchmark, and it justifies: enabling the vendored,
  byte-pristine `blake3_neon.c` (NEON is baseline on ARMv8) + `BLAKE3_USE_NEON=1`
  measures **~830 → ~1900 MiB/s (2.3×)** on this ARM core with the AEAD/tamper
  vectors still passing. An ~8-line ARM-gated CMake change; left as **tracked
  perf debt pending a greenlight to touch `third_party/`** (a build-config
  change with Stratum-wide blast radius; the pre-apply gate is a full-suite run
  with NEON, which validates the hashes are byte-identical — BLAKE3 SIMD is
  bit-for-bit the portable hash, so existing pools' Merkle/CAS stay valid).
- **The XChaCha20-SIV fallback is ~40× slower than AEGIS-256** (~200 MB/s). It
  is the AEAD only on hardware *without* AES acceleration; the Thylacine ARM64
  target has the crypto extensions, so AEGIS-256 is used. On an AES-less
  substrate the data path would be AEAD-bound at ~200 MB/s — a documented
  fallback characteristic, not a target-hardware regression.
- **The dcache is per-`stm_sync` (per-pool), 16 entries / 64 MiB.** It is sized
  for the REVENANT re-read pattern (one binary's text), not a general page
  cache. A working set wider than 16 hot extents thrashes (LRU); a larger /
  adaptive cache is future work if a workload needs it. There is no cross-mount
  sharing (each pool's plaintext stays in its own sync).
- **The cache is read-only-populated.** A freshly *written* extent is not
  cached until first read; the write path encrypts, it does not pre-warm the
  plaintext cache.

---

## 32.9 Status

Implemented (Area E): the dcache (`src/sync/sync.c`), the
`stm_sync_dcache_stats` accessor (`include/stratum/sync.h`), the two
correctness regressions (`tests/test_fs.c`), and the crypto throughput baseline
(`tests/bench_crypto.c`). The BLAKE3-NEON SIMD enable is tracked perf debt
(32.8). Closed list: `memory/audit_stratum_E_closed_list.md`.
