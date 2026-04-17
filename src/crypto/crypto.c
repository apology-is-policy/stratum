#include "stratum/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef STM_HAVE_CRYPTO
#include <sodium.h>
#endif

struct stm_crypto {
    uint8_t key[STM_CRYPTO_KEY_LEN];
};

#ifdef STM_HAVE_CRYPTO

static void ensure_sodium_init(void)
{
    static int done;
    if (!done) { (void)sodium_init(); done = 1; }
}

int stm_crypto_init(const uint8_t *key, struct stm_crypto **ctx)
{
    struct stm_crypto *c;
    ensure_sodium_init();
    c = calloc(1, sizeof(*c));
    if (!c) return -ENOMEM;
    memcpy(c->key, key, STM_CRYPTO_KEY_LEN);
    *ctx = c;
    return 0;
}

/* Build the 24-byte nonce from (paddr, write_gen). Layout is:
 *     bytes  0..7 : paddr_le64
 *     bytes  8..15: write_gen_le64
 *     bytes 16..23: zero padding
 * This keeps the same paddr under different nonces across free+realloc
 * cycles as long as write_gen advances (which it does: it's the sync
 * generation at encrypt time). */
static void build_nonce(uint8_t nonce[STM_CRYPTO_NONCE_LEN],
                        uint64_t block_addr, uint64_t write_gen)
{
    le64 addr_le = cpu_to_le64(block_addr);
    le64 gen_le  = cpu_to_le64(write_gen);
    memset(nonce, 0, STM_CRYPTO_NONCE_LEN);
    memcpy(nonce,     &addr_le, sizeof(addr_le));
    memcpy(nonce + 8, &gen_le,  sizeof(gen_le));
}

int stm_crypto_encrypt(struct stm_crypto *ctx,
                       uint64_t block_addr, uint64_t write_gen,
                       const void *plain, uint32_t plain_len,
                       void *cipher, uint32_t *cipher_len)
{
    uint8_t nonce[STM_CRYPTO_NONCE_LEN];
    unsigned long long clen;
    build_nonce(nonce, block_addr, write_gen);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher, &clen, plain, plain_len,
            NULL, 0, NULL, nonce, ctx->key) != 0)
        return -EIO;

    *cipher_len = (uint32_t)clen;
    return 0;
}

int stm_crypto_decrypt(struct stm_crypto *ctx,
                       uint64_t block_addr, uint64_t write_gen,
                       const void *cipher, uint32_t cipher_len,
                       void *plain, uint32_t *plain_len)
{
    uint8_t nonce[STM_CRYPTO_NONCE_LEN];
    unsigned long long mlen;
    build_nonce(nonce, block_addr, write_gen);

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, &mlen, NULL, cipher, cipher_len,
            NULL, 0, nonce, ctx->key) != 0)
        return -EIO;

    *plain_len = (uint32_t)mlen;
    return 0;
}

void stm_crypto_free(struct stm_crypto *ctx)
{
    if (!ctx) return;
    sodium_memzero(ctx->key, STM_CRYPTO_KEY_LEN);
    free(ctx);
}

int stm_crypto_derive_key(const char *pass, size_t pass_len,
                          const uint8_t *salt, uint8_t *key_out)
{
    ensure_sodium_init();
    if (crypto_pwhash(key_out, STM_CRYPTO_KEY_LEN,
                      pass, pass_len, salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -ENOMEM;
    return 0;
}

int stm_crypto_wrap_key(const uint8_t *kek, const uint8_t *dek,
                        uint8_t *wrapped, uint8_t *nonce_out)
{
    unsigned long long clen;
    ensure_sodium_init();
    randombytes_buf(nonce_out, STM_CRYPTO_NONCE_LEN);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            wrapped, &clen, dek, STM_CRYPTO_KEY_LEN,
            NULL, 0, NULL, nonce_out, kek) != 0)
        return -EIO;
    return 0;
}

int stm_crypto_unwrap_key(const uint8_t *kek,
                          const uint8_t *wrapped, const uint8_t *nonce,
                          uint8_t *dek_out)
{
    unsigned long long mlen;
    ensure_sodium_init();
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            dek_out, &mlen, NULL,
            wrapped, STM_CRYPTO_KEY_LEN + STM_CRYPTO_TAG_LEN,
            NULL, 0, nonce, kek) != 0)
        return -EACCES;
    return 0;
}

void stm_crypto_random(void *buf, size_t len)
{
    ensure_sodium_init();
    randombytes_buf(buf, len);
}

#else /* !STM_HAVE_CRYPTO */

int  stm_crypto_init(const uint8_t *key, struct stm_crypto **ctx)
    { (void)key; *ctx = NULL; return -ENOTSUP; }
int  stm_crypto_encrypt(struct stm_crypto *ctx, uint64_t a, uint64_t g,
                        const void *p, uint32_t pl, void *c, uint32_t *cl)
    { (void)ctx;(void)a;(void)g;(void)p;(void)pl;(void)c;(void)cl; return -ENOTSUP; }
int  stm_crypto_decrypt(struct stm_crypto *ctx, uint64_t a, uint64_t g,
                        const void *c, uint32_t cl, void *p, uint32_t *pl)
    { (void)ctx;(void)a;(void)g;(void)c;(void)cl;(void)p;(void)pl; return -ENOTSUP; }
void stm_crypto_free(struct stm_crypto *ctx) { (void)ctx; }
int  stm_crypto_derive_key(const char *p, size_t l,
                           const uint8_t *s, uint8_t *k)
    { (void)p;(void)l;(void)s;(void)k; return -ENOTSUP; }
int  stm_crypto_wrap_key(const uint8_t *kek, const uint8_t *dek,
                         uint8_t *w, uint8_t *n)
    { (void)kek;(void)dek;(void)w;(void)n; return -ENOTSUP; }
int  stm_crypto_unwrap_key(const uint8_t *kek, const uint8_t *w,
                           const uint8_t *n, uint8_t *d)
    { (void)kek;(void)w;(void)n;(void)d; return -ENOTSUP; }
void stm_crypto_random(void *buf, size_t len)
    { (void)buf; (void)len; }

#endif
