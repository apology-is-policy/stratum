# 01 — Crypto + hash

## Purpose

Primitive crypto operations used across every other layer. This file
covers `include/stratum/crypto.h` (cipher + KDF + passphrase + wrap)
and `include/stratum/hash.h` (BLAKE3 + xxHash). The crypto module is
a thin wrapper over libsodium + liboqs (optional); the hash module
wraps vendored BLAKE3 + xxHash reference impls.

Crypto primitives have no moving state of their own — nonces are
minted by the commit coordinator (sync), keys are owned by the
keyschema module. This layer only *consumes* inputs and *produces*
ciphertext / tags / hashes. Everything here is referentially
transparent (given the same inputs, same outputs) except for
`stm_random_bytes` and the ephemeral-keygen path inside
`stm_hybrid_wrap`.

Dependencies: libsodium (required), liboqs (optional — if absent,
ML-KEM-768 silently degrades to zero-padded slots so the wire format
stays identical).

## Public API

### AEAD

Two modes, selectable per dataset:

| Mode | Key | Nonce | Tag | Source |
|---|---|---|---|---|
| `STM_AEAD_AEGIS256` | 32 B | 32 B | 32 B | libsodium `crypto_aead_aegis256` |
| `STM_AEAD_XCHACHA20_SIV` | 64 B (2×32: K_MAC ‖ K_ENC) | 32 B | 16 B | In-tree HMAC-SHA256-SIV over libsodium primitives |

```c
stm_aead_mode stm_aead_autodetect(void);     // AEGIS if AES-NI/ARMv8-crypto, else SIV
size_t        stm_aead_tag_len(mode);
size_t        stm_aead_key_len(mode);

stm_status stm_aead_encrypt(mode, key, nonce[32],
                             ad, ad_len,
                             pt, pt_len,
                             ct_and_tag, &out_len);
stm_status stm_aead_decrypt(mode, key, nonce[32],
                             ad, ad_len,
                             ct_and_tag, ct_and_tag_len,
                             pt, &out_len);
```

- Tag is appended to ciphertext (`ct || tag`), not prepended.
- `ad` may be NULL / `ad_len` = 0.
- Decrypt on tamper returns `STM_EBADTAG` and does NOT write
  plaintext.
- Nonce uniqueness is the caller's obligation — the module does NOT
  reject duplicates. See [nonce construction](#nonce-construction).

### KDF

```c
void       stm_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk[32]);
stm_status stm_hkdf_sha256_expand (prk[32], info, info_len, okm, okm_len);
stm_status stm_hkdf_sha256        (salt, salt_len, ikm, ikm_len,
                                    info, info_len, okm, okm_len);
```

RFC 5869, SHA-256. Thin wrappers over libsodium's
`crypto_auth_hmacsha256`. `okm_len` capped at 255 × 32 = 8160 bytes
per RFC.

### Passphrase derivation

```c
stm_argon2id_params stm_argon2id_params_interactive(salt[16]);  // ~100 ms laptop
stm_argon2id_params stm_argon2id_params_sensitive  (salt[16]);  // ~1 s
stm_status stm_argon2id(params, passphrase, pass_len, out, out_len);
```

Forward to libsodium `crypto_pwhash` with alg=ARGON2ID13.
`parallelism` forced to 1 (libsodium limitation). Used at pool
create / passphrase change; the derived bytes unwrap the PQ-hybrid
seed that protects the pool's master key.

### Public-key primitives

Classical — always available:

```c
#define STM_X25519_PK_LEN 32
#define STM_X25519_SK_LEN 32
#define STM_X25519_SS_LEN 32

void       stm_x25519_keygen(pk[32], sk[32]);
stm_status stm_x25519_dh    (sk[32], peer_pk[32], ss[32]);
```

Post-quantum — conditional on liboqs:

```c
#define STM_MLKEM768_PK_LEN  1184
#define STM_MLKEM768_SK_LEN  2400
#define STM_MLKEM768_CT_LEN  1088
#define STM_MLKEM768_SS_LEN    32

bool stm_mlkem768_available(void);                        // runtime check
stm_status stm_mlkem768_keygen(pk, sk);
stm_status stm_mlkem768_encap (peer_pk, ct, ss);
stm_status stm_mlkem768_decap (sk, ct, ss);
```

If liboqs is absent or `stm_mlkem768_available` returns false,
callers up the stack (hybrid_wrap) fill the ML-KEM slot with zeros
and skip decap. The ciphertext layout is unchanged so a PQ-disabled
pool can still be opened by a PQ-enabled build (and vice versa — a
PQ-enabled wrapper writing to disk produces a ct that a PQ-disabled
reader can unwrap by detecting the zero ml-kem slot).

### PQ-hybrid wrap

```c
#define STM_HYBRID_PK_LEN     1216   // X25519 + ML-KEM-768 PKs
#define STM_HYBRID_SK_LEN     2432
#define STM_HYBRID_CT_LEN     1120
#define STM_HYBRID_WRAP_OVERHEAD  (STM_HYBRID_CT_LEN + 24 + 16)  // 1160

stm_status stm_hybrid_keygen(pk[1216], sk[2432]);

stm_status stm_hybrid_wrap  (pk, ad, ad_len, dek, dek_len,
                              wrapped, &out_len);        // out_len = dek_len + 1160
stm_status stm_hybrid_unwrap(sk, ad, ad_len,
                              wrapped, wrapped_len,
                              dek, &out_dek_len);
```

Wire format of `wrapped`:

```
[ 0 ..   32)  ephemeral_x25519_pk
[32 .. 1120)  mlkem_ct                     (zero-filled if liboqs absent)
[1120 .. 1144) wrap_nonce (random per wrap, 24 bytes)
[1144 ..     ) XChaCha20-Poly1305(K, nonce) of DEK || 16-byte Poly1305 tag
```

Shared key derivation:

```
ss1 = X25519(ephem_sk, peer_x25519_pk)                       32 B
ss2 = ML-KEM-768.{encap,decap}(peer_mlkem_pk)                32 B  (zero if absent)
K   = HKDF-SHA256(salt=ephem_pk||mlkem_ct, ikm=ss1||ss2,
                  info="stratum-wrap-v1", okm_len=32)         32 B
```

Wrap AD is caller-provided and part of the XChaCha20-Poly1305 AD
input — any AD tamper fails tag verification. R10 P2-2 pins the AD
to `pool_uuid || dataset_id || key_id` so a retired wrapped blob
cannot be swapped into a CURRENT slot, nor relocated across pools.

### Hashing

```c
// BLAKE3-256 (hash.h)
#define STM_BLAKE3_HASH_LEN 32
void stm_blake3        (data, len, &hash);
void stm_blake3_keyed  (key[32], data, len, &hash);
void stm_blake3_derive_key(context, ikm, ikm_len, out, out_len);

// Streaming
stm_blake3_ctx *stm_blake3_new      (void);
stm_blake3_ctx *stm_blake3_new_keyed(key[32]);
stm_blake3_ctx *stm_blake3_new_kdf  (context);
void stm_blake3_update(ctx, data, len);
void stm_blake3_final (ctx, out, out_len);          // arbitrary out_len
void stm_blake3_reset (ctx);
void stm_blake3_free  (ctx);

// xxHash (fast, non-cryptographic)
uint64_t stm_xxh3_64         (data, len);
uint64_t stm_xxh3_64_seeded  (data, len, seed);
void     stm_xxh3_128        (data, len, &hash);    // stm_xxh3_128_hash = {uint64[2]}
```

BLAKE3 is used wherever integrity matters (Merkle chain, bp_csum,
`roster_hash`, truncated-BLAKE3 per-node csums). xxHash3-64 is used
only for non-cryptographic integrity (unencrypted-extent csum field
`se_xxh`; in-memory structural hashing). xxHash3-128 is the
unencrypted-mode superblock csum on v1; v2 retains the helper for
parity but the current superblock path uses BLAKE3 chains.

### Random

```c
void stm_random_bytes(void *out, size_t n);
```

Thin wrapper over libsodium `randombytes_buf` (kernel CSPRNG:
`getrandom(2)` on Linux, `getentropy(3)` on macOS, `CryptGenRandom`
on Windows). Used for: pool-UUID, device-UUID, nonce seeds,
ephemeral X25519 keys, wrap_nonce.

### Constant-time helpers

```c
bool stm_ct_equal(const void *a, const void *b, size_t n);   // constant-time
void stm_ct_memzero(void *p, size_t n);                       // zero-on-free
```

`stm_ct_equal` is used for AEAD tag comparison (defense-in-depth —
libsodium's own compare is already constant-time, but we don't rely
on that contract). `stm_ct_memzero` wipes plaintext key material
before free; uses `sodium_memzero` underneath which the compiler
cannot optimize away.

## Implementation

### AEGIS-256

`src/crypto/aead_aegis256.c` (56 lines). Direct pass-through to
libsodium's `crypto_aead_aegis256_encrypt` /
`_decrypt_detached`. Nothing custom — the tag is 32 bytes
(libsodium's choice), the nonce is 32 bytes. AEGIS is the default on
hardware with AES acceleration because it's ~5× faster than
XChaCha20 on such CPUs.

### XChaCha20-SIV (custom construction)

`src/crypto/aead_xchacha20_siv.c` (220 lines). Stratum-specific
HMAC-SHA256-based SIV, NOT a published RFC.

The construction:

```
Key K (64 bytes) = K_MAC (32 B) || K_ENC (32 B)

Encrypt(K, N32, AD, PT):
    mac_input = N32[0:32]                            // full 32-byte nonce
             || le64(|AD|) || AD
             || le64(|PT|) || PT
    V   = HMAC-SHA256(K_MAC, mac_input)               // 32 B
    TAG = V[0:16]                                     // 16 B on-disk
    xnonce24 = TAG || N32[24:32]                      // XChaCha20 nonce
    CT  = XChaCha20(K_ENC, xnonce24, PT)
    return TAG || CT

Decrypt verifies by recomputing V' and constant-time-comparing
V'[0:16] to TAG; on mismatch returns STM_EBADTAG and writes no PT.
```

Security properties (documented at `src/crypto/aead_xchacha20_siv.c:30`):

- **Unique `(N32, AD, PT)`**: TAG is a cryptographic MAC under
  HMAC-SHA256. XChaCha20 encrypts with an effectively PRF-output
  nonce, so no CPA weakness.
- **Repeated `(N32, AD, PT)`**: SIV property. Attacker learns only
  that two ciphertexts encode the same plaintext under the same AD
  and nonce — no CPA break.
- **Repeated `N32` but differing `PT`**: different TAG → different
  `xnonce24` → different CT. No cross-plaintext leakage.
- **AD binding**: full AD enters MAC input; any tamper fails the
  tag check.
- **Pool-UUID domain separation**: `N32[24:32]` carries pool-UUID
  bits and enters both the MAC input AND the XChaCha20 nonce, so
  cross-pool ciphertext splicing fails at two independent layers.

Why SIV: v2's key-derivation architecture (per-object keys derived
from AD) makes catastrophic `(key, nonce)` reuse impossible in
principle, but SIV adds a belt-and-suspenders layer against a
caller bug that synthesizes duplicate nonces. AEGIS would be faster
but is not nonce-misuse-resistant.

### PQ-hybrid wrap

`src/crypto/hybrid_wrap.c` (235 lines). HPKE-style but not
HPKE-spec-compliant — it's a narrow wrapper designed only for "wrap
this 32-byte DEK." Steps:

1. Generate ephemeral X25519 keypair.
2. `ss1 = X25519(ephem_sk, peer_x25519_pk)`.
3. If liboqs present: `ss2 = ML-KEM-768.encap(peer_mlkem_pk)`,
   produces `mlkem_ct`. Else: `ss2 = 0`, `mlkem_ct = 0`.
4. `K = HKDF-SHA256(salt=ephem_pk||mlkem_ct, ikm=ss1||ss2, info="stratum-wrap-v1", 32)`.
5. `wrap_nonce = random(24)`.
6. `ct_and_tag = XChaCha20-Poly1305(K, wrap_nonce, AD, DEK)`.
7. Wipe `ss1`, `ss2`, `ikm`, `K`.
8. Emit `ephem_pk || mlkem_ct || wrap_nonce || ct_and_tag`.

Decrypt reverses. Constants all from libsodium / liboqs — we don't
hand-roll X25519 or ML-KEM.

### Init

`src/crypto/init.c` is a one-shot `stm_crypto_init()` that calls
`sodium_init()`. Tests call it once per process. Libsodium's self-
init is re-entrant so a second call is a no-op.

## Nonce construction

Nonces are not minted here. The pattern is:

**Metadata nodes** (btree / alloc tree / alloc-roots / keyschema):
`src/btree_store/crypt.c:63` `build_nonce`:

```
nonce (32 B) = paddr (8 LE) || gen (8 LE) || pool_uuid (16 LE)
AD    (32 B) = pool_uuid (16 LE) || device_uuid (16 LE)
```

Uniqueness guarantees:
- `paddr` is unique within a gen (bootstrap + alloc deferred-free
  prevent paddr reuse within a commit — `allocator.tla`).
- `gen` is monotone (sync.tla MountGenBump + quorum.tla
  AuthoritativeMono).
- `pool_uuid` scopes nonce space to one pool.

Plus: in multi-device pools, paddr's top 16 bits encode device_id,
so two per-device alloc trees reserving the same start_block
produce distinct paddrs. `metadata_nonce.tla` pins the full
invariant; its buggy config (`DeviceStampPaddrs = FALSE`, modeling
the pre-R15 impl) finds a depth-5 counterexample where two devices
write `(paddr=1, gen=1)` under a shared key.

**Extents** (data blocks): per-extent AD struct containing
`(dataset_id, key_id, inode, offset, length, aead_mode)`;
derived extent key = HKDF(root_dek, info=AD). Each extent thus has
its own key, so nonce collisions within the key are constrained by
how many AEAD calls per extent — currently ≤1. Extent-layer nonces
are constructed in the extent manager (Phase 6) and are out of
scope for this document.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `metadata_nonce.tla` | `NonceUniqueness` on metadata-node encryption under shared `metadata_key`. Buggy config demonstrates the pre-R15 F1 collision. |
| `merkle.tla` | `MerkleRootIntegrity` — tamper of any covered node changes the uberblock's `ub_merkle_root`. (Transitively relies on BLAKE3's collision resistance, modeled as abstract hash.) |
| `key_schema.tla` | Transitions CURRENT → RETIRED → PRUNING don't lose AD-binding context; pins that rotate + unwrap compose correctly. |

`docs/SPEC-TO-CODE.md` has the full mapping from TLA actions /
invariants to the C symbols that realize them.

## Tests

| Suite | Coverage |
|---|---|
| `test_hash` (9 tests) | BLAKE3 empty / `abc` / long / stream==oneshot / keyed / derive_key; xxH3-64 known / empty / seeded; xxH3-128 distinct. |
| `test_crypto` (21 tests) | AEGIS-256 roundtrip + tamper (ct / ad) + wrong-nonce; XChaCha20-SIV roundtrip + deterministic + nonce-misuse-differs-on-diff-pt + tamper (ct / tag) + empty PT + long AD + nonce-high-bytes-affect-tag + contiguous-tag-and-ct layout; HKDF RFC 5869 case 1; Argon2id deterministic + salt-differs; X25519 DH-agreement; random-bytes-nonzero; ct_equal basics; ct_memzero clears; hybrid-wrap zero-mlkem-pk roundtrip. |
| `test_hybrid` (6 tests) | Full PQ-hybrid roundtrip (small + large DEK); ct tamper fails; wrong sk fails; AD mismatch fails; wrap output differs across calls (randomness). |

## Status

- [x] AEGIS-256 AEAD (libsodium). `src/crypto/aead_aegis256.c`.
- [x] XChaCha20-SIV AEAD (custom SIV over libsodium).
      `src/crypto/aead_xchacha20_siv.c`.
- [x] HKDF-SHA256. `src/crypto/hkdf.c`.
- [x] Argon2id (libsodium). `src/crypto/argon2.c`.
- [x] X25519 (libsodium). `src/crypto/x25519.c`.
- [x] ML-KEM-768 (liboqs, conditional). `src/crypto/mlkem768.c`.
- [x] PQ-hybrid wrap. `src/crypto/hybrid_wrap.c`.
- [x] BLAKE3-256 (vendored reference). `src/hash/blake3_wrap.c`.
- [x] xxHash3-64 / -128 (vendored reference). `src/hash/xxhash_wrap.c`.
- [x] CSPRNG (libsodium). `src/crypto/random.c`.
- [x] Constant-time compare + memzero. `src/crypto/ct.c`.

All Phase 1 deliverables. No planned changes to this layer through
Phase 6; Phase 7 CAS might add additional HKDF-derived sub-keys
but the primitive surface is stable.

## Known caveats

- **XChaCha20-SIV is not a published RFC**. The construction is
  documented inline at `src/crypto/aead_xchacha20_siv.c:6` and
  `docs/ARCHITECTURE.md §7.5.2`. It has not been externally
  peer-reviewed; the security argument is spelled out but unverified
  by an independent cryptographer as of this writing.
- **ML-KEM-768 wire-format stability**: we commit to ML-KEM-768
  (NIST FIPS 203). If NIST finalizes under a different name or
  tweaks parameters, the wire format may require a bump. The liboqs
  version installed determines which parameter set we get; we do
  not verify a specific fingerprint against liboqs's implementation.
- **No key rotation for the pool metadata key**: `dataset_id == 0`
  (pool metadata) is the only DEK that cannot be rotated; doing so
  would require re-encrypting every metadata node under the new
  key, a sweep that is deferred (ARCH §7.7.3). All other dataset
  keys rotate freely via `stm_sync_rotate_dataset_key`.
- **Libsodium's `parallelism = 1` limitation** on Argon2id means we
  can't fully exploit multi-core derivation; not a bottleneck for
  typical pool-create workflows.
