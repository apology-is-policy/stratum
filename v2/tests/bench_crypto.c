/* SPDX-License-Identifier: ISC */
/*
 * bench_crypto -- Stratum Stabilization Area E crypto/integrity throughput
 * baseline. THE arc's G2 measurement reference: the cryptographic layer is
 * the ONE accepted bandwidth delta versus a mature COW FS (BTRFS/ZFS), so
 * every other area's throughput is judged against the numbers measured here.
 *
 * Three layers, isolated:
 *
 *   AEAD (the dominant Stratum-specific cost) -- stm_aead_encrypt /
 *     stm_aead_decrypt MB/s for BOTH modes (AEGIS-256 on AES-accelerated
 *     hardware, XChaCha20-SIV fallback), across the extent sizes a real
 *     read/write moves (4 KiB .. 8 MiB recordsize). This is the per-byte
 *     ceiling the data path cannot beat; the read path pays the DECRYPT
 *     column once per uncached extent slice.
 *
 *   Integrity hash -- BLAKE3-256 (the Merkle input on encrypted volumes)
 *     and xxHash3-64 (the per-extent csum on unencrypted volumes) MB/s.
 *     The charter's "integrity is near-parity" claim is MEASURED here:
 *     BTRFS/ZFS checksum too, so only the AEAD column is a true delta.
 *
 *   The #343 dcache mechanism -- a repeated read of one extent turns the
 *     AEAD DECRYPT into a plaintext memcpy. The decrypt-1MiB vs memcpy-1MiB
 *     row is the per-read crypto cost the cache recovers (the "with/without
 *     AEAD" axis the charter wants, at the read path: a miss pays decrypt,
 *     a hit pays memcpy).
 *
 * The "with/without AEAD" isolation the charter mandates is done HERE at the
 * primitive level (Stratum has no plaintext FS mode -- stm_fs_format_opts
 * requires a keyfile -- so the FS itself cannot toggle the AEAD off; the
 * primitive bench is the honest isolation).
 *
 * Build + run on the NON-sanitized build (real timing):
 *   cmake --build build --target bench_crypto -j8
 *   ./build/tests/bench_crypto
 *   STM_BENCH_MIB=512 ./build/tests/bench_crypto   # more bytes per point
 */

#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned BYTES_MIB = 256u;     /* total bytes processed per measurement */

static unsigned env_u(const char *k, unsigned dflt)
{
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    unsigned long n = strtoul(v, NULL, 10);
    return n ? (unsigned)n : dflt;
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Iterations to move ~BYTES_MIB total at this record size (>= 4 so the
 * largest record still measures a few passes). */
static uint64_t iters_for(size_t sz)
{
    uint64_t total = (uint64_t)BYTES_MIB * 1024u * 1024u;
    uint64_t n = total / (uint64_t)sz;
    return n < 4u ? 4u : n;
}

static const char *mode_name(stm_aead_mode m)
{
    switch (m) {
    case STM_AEAD_AEGIS256:      return "AEGIS-256";
    case STM_AEAD_XCHACHA20_SIV: return "XChaCha20-SIV";
    default:                     return "?";
    }
}

/* Encrypt+decrypt MB/s for one (mode, size). Decrypt times a real verified
 * decrypt of a once-encrypted ciphertext (AEAD verifies the whole tag). */
static void bench_aead(stm_aead_mode mode, size_t sz)
{
    size_t keylen = stm_aead_key_len(mode);
    size_t taglen = stm_aead_tag_len(mode);
    uint8_t key[STM_AEAD_KEY_LEN_MAX];
    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad[16];
    stm_random_bytes(key, keylen);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(ad, sizeof ad);

    uint8_t *pt  = malloc(sz);
    uint8_t *ct  = malloc(sz + taglen);
    uint8_t *pt2 = malloc(sz);
    if (!pt || !ct || !pt2) { fprintf(stderr, "OOM at sz=%zu\n", sz); free(pt); free(ct); free(pt2); return; }
    stm_random_bytes(pt, sz);

    size_t ctlen = 0, ptlen = 0;
    if (stm_aead_encrypt(mode, key, nonce, ad, sizeof ad, pt, sz, ct, &ctlen) != STM_OK) {
        fprintf(stderr, "%s: encrypt failed at sz=%zu\n", mode_name(mode), sz);
        goto done;
    }

    uint64_t iters = iters_for(sz);

    /* Encrypt throughput. Vary nonce[0] each pass so a real unique-nonce
     * encrypt is measured (no cipher-internal short-circuit). */
    (void)stm_aead_encrypt(mode, key, nonce, ad, sizeof ad, pt, sz, ct, &ctlen); /* warm */
    double t0 = now_s();
    for (uint64_t i = 0; i < iters; i++) {
        nonce[0] = (uint8_t)i; nonce[1] = (uint8_t)(i >> 8);
        (void)stm_aead_encrypt(mode, key, nonce, ad, sizeof ad, pt, sz, ct, &ctlen);
    }
    double enc_s = now_s() - t0;

    /* Re-encrypt under the final nonce so the timed decrypts verify. */
    (void)stm_aead_encrypt(mode, key, nonce, ad, sizeof ad, pt, sz, ct, &ctlen);
    (void)stm_aead_decrypt(mode, key, nonce, ad, sizeof ad, ct, ctlen, pt2, &ptlen); /* warm */
    t0 = now_s();
    for (uint64_t i = 0; i < iters; i++) {
        if (stm_aead_decrypt(mode, key, nonce, ad, sizeof ad, ct, ctlen, pt2, &ptlen) != STM_OK) {
            fprintf(stderr, "%s: decrypt verify failed at sz=%zu\n", mode_name(mode), sz);
            goto done;
        }
    }
    double dec_s = now_s() - t0;

    double mib = (double)sz * (double)iters / (1024.0 * 1024.0);
    fprintf(stderr, "  %-14s %7zu B   enc %8.1f MiB/s   dec %8.1f MiB/s\n",
            mode_name(mode), sz,
            enc_s > 0 ? mib / enc_s : 0.0,
            dec_s > 0 ? mib / dec_s : 0.0);
done:
    free(pt); free(ct); free(pt2);
}

static void bench_hash(size_t sz)
{
    uint8_t *buf = malloc(sz);
    if (!buf) { fprintf(stderr, "OOM at sz=%zu\n", sz); return; }
    stm_random_bytes(buf, sz);
    uint64_t iters = iters_for(sz);

    stm_blake3_hash bh;
    stm_blake3(buf, sz, &bh);                 /* warm */
    double t0 = now_s();
    for (uint64_t i = 0; i < iters; i++) stm_blake3(buf, sz, &bh);
    double b3_s = now_s() - t0;

    volatile uint64_t sink = 0;
    sink ^= stm_xxh3_64(buf, sz);             /* warm */
    t0 = now_s();
    for (uint64_t i = 0; i < iters; i++) sink ^= stm_xxh3_64(buf, sz);
    double xx_s = now_s() - t0;
    (void)sink;

    double mib = (double)sz * (double)iters / (1024.0 * 1024.0);
    fprintf(stderr, "  %-14s %7zu B   blake3 %8.1f MiB/s   xxh3 %9.1f MiB/s\n",
            "integrity", sz,
            b3_s > 0 ? mib / b3_s : 0.0,
            xx_s > 0 ? mib / xx_s : 0.0);
    free(buf);
}

/* The #343 dcache mechanism, at the primitive level: a cache MISS decrypts the
 * whole extent (the AEAD dec column), a cache HIT memcpy's the cached
 * plaintext. The ratio is the per-read speedup the dcache delivers when an
 * extent is re-read (REVENANT demand-paged exec faults one binary's text in
 * many page slices -> one decrypt, then all hits). */
static void bench_dcache_mechanism(stm_aead_mode mode)
{
    const size_t sz = 1024u * 1024u;          /* a representative 1 MiB extent */
    size_t keylen = stm_aead_key_len(mode);
    size_t taglen = stm_aead_tag_len(mode);
    uint8_t key[STM_AEAD_KEY_LEN_MAX], nonce[STM_AEAD_NONCE_LEN], ad[16];
    stm_random_bytes(key, keylen);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(ad, sizeof ad);

    uint8_t *pt = malloc(sz), *ct = malloc(sz + taglen), *dst = malloc(sz), *cached = malloc(sz);
    if (!pt || !ct || !dst || !cached) { fprintf(stderr, "OOM\n"); goto done; }
    stm_random_bytes(pt, sz);
    size_t ctlen = 0, ptlen = 0;
    if (stm_aead_encrypt(mode, key, nonce, ad, sizeof ad, pt, sz, ct, &ctlen) != STM_OK) goto done;
    memcpy(cached, pt, sz);                    /* the resident plaintext a hit memcpy's */

    uint64_t iters = iters_for(sz);

    /* MISS: decrypt the whole extent each read. */
    (void)stm_aead_decrypt(mode, key, nonce, ad, sizeof ad, ct, ctlen, dst, &ptlen);
    double t0 = now_s();
    for (uint64_t i = 0; i < iters; i++)
        (void)stm_aead_decrypt(mode, key, nonce, ad, sizeof ad, ct, ctlen, dst, &ptlen);
    double miss_s = now_s() - t0;

    /* HIT: memcpy the cached plaintext. A compiler barrier after each copy
     * makes the write observable, so dead-store elimination cannot collapse
     * the loop (dst == cached post-memcpy) and fake the speedup (F1). */
    memcpy(dst, cached, sz);
    t0 = now_s();
    for (uint64_t i = 0; i < iters; i++) {
        memcpy(dst, cached, sz);
        __asm__ volatile("" : : "r"(dst) : "memory");
    }
    double hit_s = now_s() - t0;

    double mib = (double)sz * (double)iters / (1024.0 * 1024.0);
    double miss_mbs = miss_s > 0 ? mib / miss_s : 0.0;
    double hit_mbs  = hit_s  > 0 ? mib / hit_s  : 0.0;
    fprintf(stderr, "  dcache 1 MiB   read MISS (decrypt) %8.1f MiB/s   "
            "read HIT (memcpy) %9.1f MiB/s   speedup %.1fx\n",
            miss_mbs, hit_mbs, miss_mbs > 0 ? hit_mbs / miss_mbs : 0.0);
done:
    free(pt); free(ct); free(dst); free(cached);
}

int main(void)
{
    if (stm_crypto_init() != STM_OK) { fprintf(stderr, "crypto init failed\n"); return 1; }
    BYTES_MIB = env_u("STM_BENCH_MIB", 256u);

    stm_aead_mode picked = stm_aead_autodetect();
    fprintf(stderr, "bench_crypto: ~%u MiB/point, autodetect picks %s "
            "(the production cipher on this CPU)\n\n", BYTES_MIB, mode_name(picked));

    const size_t sizes[] = { 4096u, 64u * 1024u, 1024u * 1024u, 8u * 1024u * 1024u };
    const size_t n_sizes = sizeof sizes / sizeof sizes[0];

    fprintf(stderr, "AEAD (the accepted crypto delta vs BTRFS/ZFS):\n");
    stm_aead_mode modes[] = { STM_AEAD_AEGIS256, STM_AEAD_XCHACHA20_SIV };
    for (size_t m = 0; m < 2; m++)
        for (size_t i = 0; i < n_sizes; i++) bench_aead(modes[m], sizes[i]);

    fprintf(stderr, "\nIntegrity hash (near-parity -- BTRFS/ZFS checksum too):\n");
    for (size_t i = 0; i < n_sizes; i++) bench_hash(sizes[i]);

    fprintf(stderr, "\nThe #343 dcache (decrypt -> memcpy on a re-read):\n");
    bench_dcache_mechanism(picked);

    return 0;
}
