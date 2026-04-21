# P4-3b priming — AEAD on metadata nodes

**For the next Claude instance after compaction.** Working playbook
for landing Phase 4 chunk P4-3b (AEAD encryption of every metadata
node at the btree_store boundary). Delete this doc after P4-3b +
R9 audit close.

## Start here (first 5 minutes)

1. Verify tip is `cb9671f` on `main`, working tree clean:
   ```bash
   cd /Users/northkillpd/projects/stratum && git log --oneline -5 && git status
   ```
2. Verify 20/20 suites green on default:
   ```bash
   cd v2 && ctest --test-dir build --output-on-failure 2>&1 | tail -5
   ```
3. Read the design in `v2/docs/phase4-status.md` §"P4-3b (next)" —
   the on-disk layout, nonce/AD construction, AEAD choice, and
   integration surfaces are specified there.
4. Confirm autonomy: the user authorized "continue autonomously
   unless a decision point warrants input". P4-3b has no known
   decision points — the design was signed off when P4-3a landed.

## Context snapshot

- **Phase 3**: CLOSED (commit `3929d61` + `b8f2315` fuzzer).
- **Phase 4 landed**:
  - `54b3c8b` → `ee3600c`: P4-1 Merkle scaffold + R8 fixes.
  - `65c4c76`: P4-6 `merkle.tla` (TLC 83169 states).
  - `cb9671f`: P4-3a metadata-key lifecycle (key at
    `ub_key_schema[0..32]`, generated/persisted/recovered but
    unused by write path).
- **Audit state**: R0-R8 closed. Preamble lives at
  `memory/audit_v2_r0_closed_list.md`.
- **Tests**: 20 suites, 80+ cases, green on default/ASan/TSan.

## P4-3b design recap

(Full version in phase4-status.md. This is the TL;DR.)

**Encrypted metadata node on-disk layout (128 KiB = 131072 B)**:
```
[0                             .. 131040)   AEAD ciphertext   (131040 B)
[131040                        .. 131072)   AEAD tag          (     32 B)
```
- `bp_csum` in parent/uberblock = `BLAKE3(on-disk[0..131040))` —
  covers ciphertext, NOT the tag. Same definition as P4-1's
  `bp_csum`; no semantic change.
- Tag tamper is caught by AEAD decrypt (STM_ECORRUPT).
- Ciphertext tamper is caught by Merkle-chain via `bp_csum`.
- Plaintext (= decrypted ciphertext) is identical to what
  `stm_btnode_*_encode` produces today, including the trailing-32
  self-csum slot at `[131040..131072)` of the plaintext (now
  shadowed by the AEAD tag on disk).

**AEAD**: AEGIS-256.
- Key: 32 B from `stm_sync.metadata_key` (populated by P4-3a).
- Nonce (32 B): `paddr (8 LE) ‖ gen (8 LE) ‖ pool_uuid (16 LE)`.
  Uniqueness under sync.tla's MountGenBump (gen strictly
  increases per commit) + stm_bootstrap's deferred-free (paddr
  not reused within a commit).
- AD (32 B): `pool_uuid (16 LE) ‖ device_uuid (16 LE)`.

**Mandatory, not feature-flagged** — every v2 pool encrypts every
metadata node. No unencrypted path in code.

## Implementation plan (step-by-step)

### 1. New file `src/btree_store/crypt.c` + header

Create a small, testable wrapper module:

```c
// include/stratum/btree_store.h (or internal header)
typedef struct {
    const uint8_t *metadata_key;    // 32 B, borrowed
    uint64_t       pool_uuid[2];
    uint64_t       device_uuid[2];
} stm_btree_crypt_ctx;

// Encrypt in-place. `buf` is STM_BTNODE_SIZE bytes; on return,
// buf[0..131040) holds ciphertext and buf[131040..131072) holds
// the AEAD tag. Replaces whatever was in those trailing 32
// bytes at call time (which was the plaintext self-csum the
// encoder wrote — that's expected to be overwritten).
stm_status stm_btree_node_encrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf);

// Decrypt in-place. `buf` is STM_BTNODE_SIZE bytes; on success
// buf[0..131040) holds the recovered plaintext and [131040..)
// is untouched (the tag is consumed but callers shouldn't read
// it afterward). Returns STM_ECORRUPT on tag mismatch.
stm_status stm_btree_node_decrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf);
```

Internals: build nonce + AD locally (stack), call AEGIS-256 via
`stm_aegis256_encrypt` / `_decrypt` from `stratum/crypto.h`.

Write unit tests for crypt.c in `tests/test_btree_store_crypt.c`:
round-trip, tag-tamper, paddr-mismatch, gen-mismatch, different
key.

### 2. Thread `gen` + crypt_ctx through serialize/deserialize

**serialize.c** (current signature):
```c
stm_status stm_btree_store_serialize(
    stm_btree_mt *t, uint64_t gen, uint64_t tree_id,
    const stm_btree_store_vtable *vt, void *vt_ctx,
    uint64_t *out_root_paddr, uint8_t out_root_csum[32]);
```

New: add `const stm_btree_crypt_ctx *cx` parameter. `emit_leaf` /
`emit_internal` receive it. After each `stm_btnode_*_encode`, call
`stm_btree_node_encrypt(cx, paddr, gen, scratch)` BEFORE
computing csum + writing. The csum computation (`node_csum_from_buf`)
already reads from `buf[131040-32..131040]`, i.e., the last 32
bytes of the ciphertext region. Wait — re-check: `STM_BTNODE_CSUM_OFFSET
= STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE = 131040`. The csum slot
is at `[131040..131072)`. After encryption, that slot holds the
AEAD tag. So `node_csum_from_buf` would read the tag as the
"csum", which is wrong — we want csum = BLAKE3 of `[0..131040)`.

**Fix**: `node_csum_from_buf` (in serialize.c) currently does
`memcpy(out, buf + 131040, 32)`. After encryption, what's at
`[131040..131072)` is the AEAD tag, NOT a BLAKE3 hash. We need
a NEW helper:

```c
static inline void compute_bp_csum(const uint8_t *buf, uint8_t out[32]) {
    stm_blake3(buf, 131040, (stm_blake3_hash *)out);
}
```

Replace `node_csum_from_buf` calls in `emit_leaf` / `emit_internal`
with `compute_bp_csum(scratch, out_csum)` AFTER encryption. That's
the authoritative bp_csum for encrypted nodes.

**deserialize.c** symmetric: `stm_btree_store_deserialize` takes
`const stm_btree_crypt_ctx *cx` too. After `vt->read`:
1. Compute `BLAKE3(buf[0..131040))` → compare to `expected_root_csum`
   (check_merkle_link's new incarnation).
2. `stm_btree_node_decrypt(cx, paddr, gen, buf)` — recovers
   plaintext in `buf[0..131040)`.
3. Proceed with `stm_btnode_peek` / `_leaf_decode` / `_internal_decode`
   on the plaintext.
4. Note: `stm_btnode_peek`, `btnode_verify_csum`, etc. expect
   plaintext with BLAKE3 self-csum at trailing 32 bytes. The
   decrypted plaintext's trailing 32 bytes WILL be the plaintext
   self-csum the encoder wrote (unchanged by
   encrypt/decrypt round-trip) → `btnode_verify_csum` still
   passes as sanity check.

**child_record_cb** (internal nodes) also needs the crypt_ctx to
decrypt child nodes recursively. Pass through `cc.crypt_ctx`.

**gen threading**: for internal roots, all children share the same
gen (snapshot-style serialize). Add `gen` to `stm_btree_store_deserialize`
signature. Store in `child_collect` too so the per-leaf decrypt
loop has it.

### 3. Plumb through stm_alloc

`stm_alloc_load_tree_at` currently:
```c
stm_status stm_alloc_load_tree_at(stm_alloc *a, uint64_t root_paddr,
                                    const uint8_t expected_root_csum[32]);
```

Needs:
```c
stm_status stm_alloc_load_tree_at(stm_alloc *a, uint64_t root_paddr,
                                    uint64_t gen,
                                    const uint8_t expected_root_csum[32],
                                    const stm_btree_crypt_ctx *cx);
```

`stm_alloc_commit` needs to pass the crypt_ctx + commit_gen to
`stm_btree_store_serialize`. The crypt_ctx itself should live in
stm_alloc (populated via `stm_alloc_set_crypt_ctx` called from
sync or at open).

Actually simpler: `stm_alloc` stashes metadata_key + pool_uuid +
device_uuid, builds the crypt_ctx on demand. Adds three fields to
`struct stm_alloc`.

### 4. Plumb through stm_sync

`stm_sync_commit`:
- Already has metadata_key, pool_uuid, device_uuid in `struct stm_sync`.
- Builds crypt_ctx, passes to `stm_alloc_commit` (new signature).
- Passes commit_gen.

`stm_sync_open`:
- After loading metadata_key from ub_key_schema, builds crypt_ctx.
- Passes to `stm_alloc_load_tree_at(a, root, durable_gen, csum, cx)`.
- `durable_gen` = `stm_load_le64(ub.ub_gen)`.

### 5. Remove/bypass btnode's self-csum semantics for on-disk reads

**Important clarification**: after step 2's `stm_btree_node_decrypt`,
the plaintext in `buf` is EXACTLY what the encoder produced —
including the plaintext self-csum at the trailing 32 bytes. So
`btnode_verify_csum` on the DECRYPTED buf still works. No code
changes needed to btnode.c / btnode_common.c. The self-csum now
acts as a redundant plaintext-integrity check; AEAD provides the
primary cryptographic integrity.

`check_merkle_link` in serialize.c still works — but with the
understanding that the "trailing 32 bytes of on-disk buf" is now
the AEAD tag, NOT a BLAKE3 hash. So `check_merkle_link(buf,
expected)` where `expected` = parent's stored bp_csum, and
bp_csum = BLAKE3(buf[0..131040)) — we need to rewrite
check_merkle_link to compute BLAKE3 itself, not just compare
trailing 32 bytes:

```c
static inline stm_status check_merkle_link(const uint8_t *buf,
                                             const uint8_t expected[32]) {
    if (!expected) return STM_OK;
    stm_blake3_hash actual;
    stm_blake3(buf, STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE, &actual);
    if (memcmp(actual.bytes, expected, 32) != 0) return STM_ECORRUPT;
    return STM_OK;
}
```

This replaces the previous "extract trailing 32 bytes and compare"
logic (which was correct only when the trailing 32 = BLAKE3
self-csum). Now we explicitly hash the ciphertext region.

### 6. Tests

Update existing tests for new signatures:
- `tests/test_btree_store.c` — signatures changed; pass a
  `stm_btree_crypt_ctx` with a test key. Existing round-trip tests
  exercise the encrypted path transparently.
- `tests/test_alloc.c` — `stm_alloc_load_tree_at` takes gen + cx
  now. Use alloc's stashed values.
- `tests/test_sync.c` — already threads gen through
  stm_sync_open; no changes.

New tests (add to `test_btree_store.c` or a new file):
- `bstore_encrypted_round_trip` — serialize+deserialize encrypted.
  Same as existing round-trip but explicitly assert ciphertext on
  disk differs from plaintext.
- `bstore_tag_tamper_detected` — flip a byte in the AEAD tag
  region; deserialize fails STM_ECORRUPT.
- `bstore_ciphertext_tamper_detected` — flip a byte in ciphertext;
  `check_merkle_link` catches it (bp_csum mismatch) before AEAD
  has a chance to try.
- `bstore_wrong_key_fails` — serialize with key A, try to
  deserialize with key B; AEAD tag verification fails.
- `bstore_wrong_gen_fails` — tell deserialize a different gen
  than what was used to serialize; AEAD fails (nonce mismatch).
- `bstore_wrong_pool_uuid_fails` — similar.

### 7. Build + test + commit + push

Follow the standard pattern from prior chunks:
1. Build default, ASan, TSan.
2. Commit with a detailed message.
3. Push.
4. Update phase4-status.md.

### 8. Spawn R9 audit

Post-commit, spawn an Opus 4.7 soundness-prosecutor in the
background. Include the R0-R8 closed list as do-not-report
preamble. Focus:

- **Nonce uniqueness**: verify that `(paddr, gen, pool_uuid)`
  tuples are unique across the pool's lifetime. Corner cases:
  mount-bump-after-crash; paddr reuse within a commit; gen
  overflow (R7d-P2-5 already clamps at UINT64_MAX - 1).
- **AD binding**: a node written under dataset X shouldn't
  decrypt under dataset Y. (No datasets yet, but pool_uuid in AD
  ensures cross-pool replay is rejected.)
- **Key material handling**: metadata_key is passed by const
  pointer. No copies, no logging, no leakage into debug paths.
- **In-place encryption**: buf is mutated in place. Memory
  safety on encrypt failure (buf is left in undefined state —
  caller must not write it to disk).
- **Atomic-on-failure**: if encryption succeeds but vt->write
  fails, is the paddr leaked? (stm_bootstrap already handles
  this correctly, but verify the new code doesn't break it.)
- **Merkle chain under encryption**: verify that bp_csum still
  covers the full metadata image it's supposed to. A byte flip
  anywhere in the ciphertext must fail the Merkle check.
- **Cross-check against merkle.tla**: the formal model assumed
  plaintext node hashes. Encrypted hashes are a different fixed
  function but the same structural properties hold. Verify this
  reasoning holds.

### 9. R9 fixes + close

Standard audit-fix cycle. Update closed-list with R9 section.
Final push.

## Verification commands

```bash
cd /Users/northkillpd/projects/stratum/v2

# Default
cmake --build build -j && ctest --test-dir build --output-on-failure

# ASan
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure

# TSan (crash_inject ~40s under TSan; timeout bumped to 180s)
cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure

# All TLA+ specs
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
for s in sync concurrency structural balanced merge allocator merkle; do
    echo "== $s =="
    java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
        -config $s.cfg $s.tla 2>&1 | tail -3
done
```

## Trip hazards

Load-bearing invariants P4-3b MUST preserve:

1. **Nonce uniqueness** (sync.tla, R7d-P2-5): `current_gen =
   durable_gen + 1` at mount bumps strictly past any durable gen.
   Gen is bounded below UINT64_MAX - 1. Paddr not reused within a
   commit (stm_bootstrap's deferred-free).
2. **Format stability**: STM_UB_VERSION is 2 (bumped in P4-1). No
   further bump in P4-3b — on-disk btnode layout is unchanged;
   only the INTERPRETATION of the trailing 32 bytes changes
   (plaintext self-csum vs. AEAD tag), and only for encrypted
   nodes (which in v2 is all of them).
3. **Merkle chain under COW** (merkle.tla): every metadata write
   produces a new paddr with a new bp_csum propagating up. Don't
   introduce any path that encrypts a node without updating its
   parent's bp_csum.
4. **Lock order**: `fs > sync > alloc > btree-mt rwlock`.
   Encryption is CPU work — keep it inside the caller's lock
   scope (no releasing the lock mid-encrypt).
5. **Key material never touches disk in plaintext** — EXCEPT for
   the MVP P4-3a placeholder at `ub_key_schema[0..32]`, which
   IS plaintext. P4-4 will wrap this with PQ-hybrid. For P4-3b
   we accept the MVP posture.
6. **bp_csum unchanged semantically** (P4-1): BLAKE3 of
   `[0..STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)`. Same math,
   different content (ciphertext instead of plaintext).
7. **R8-P1-2**: `stm_alloc_load_tree_at` requires non-NULL
   expected_root_csum. Preserve this when adding gen/cx params.
8. **R7-P0-1**: accel_dirty invariants on rebuild failure.
   Encryption doesn't touch accel paths.
9. **R8-P0-1**: free_tree must allocate child_csums symmetrically.
   Still required; encryption doesn't change the enumeration path.

## Decision points (none expected)

P4-3b's design was signed off when P4-3a landed. Expected to proceed
autonomously through implementation + R9 + fixes. Escalate ONLY if:

- A structural issue blocks the "trailing 32 bytes = AEAD tag"
  design — e.g., AEGIS-256 tag size turns out to be != 32 bytes
  (it IS 32 per ARCH §7.5.2; double-check with stm_crypto's
  actual API).
- Multi-level tree support is needed for a real workload that
  can't fit in 2 levels (chunk 5c cap; still deferred per
  R8-P3-4).
- Per-dataset keys become urgent (P4-4); MVP's single pool key
  works for now.

## Closing checklist

- [ ] Commit P4-3b implementation + tests.
- [ ] Push to main.
- [ ] Update phase4-status.md with P4-3b landing row.
- [ ] Spawn R9 audit (opus soundness-prosecutor, background).
- [ ] On R9 completion: fix findings, commit, push.
- [ ] Update `memory/audit_v2_r0_closed_list.md` with R9 section.
- [ ] Update memory pointers (MEMORY.md, project_v2_active.md,
      project_v2_next_session.md) to reflect P4-3b landing and
      next step (P4-2 / P4-4 / P4-5 per user preference).
- [ ] Delete `v2/docs/P4-3b-priming.md` — its job is done.
