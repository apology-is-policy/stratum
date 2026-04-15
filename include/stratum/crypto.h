#ifndef STM_CRYPTO_H
#define STM_CRYPTO_H

#include "stratum/types.h"

#define STM_CRYPTO_KEY_LEN    32
#define STM_CRYPTO_NONCE_LEN  24
#define STM_CRYPTO_TAG_LEN    16
#define STM_CRYPTO_SALT_LEN   16

struct stm_crypto;

/* Initialize crypto context with a raw 32-byte DEK. */
int  stm_crypto_init(const uint8_t *key, struct stm_crypto **ctx);

/* Encrypt plain_len bytes. cipher must hold plain_len + STM_CRYPTO_TAG_LEN.
 * block_addr is used as nonce (unique per COW write). */
int  stm_crypto_encrypt(struct stm_crypto *ctx, uint64_t block_addr,
                        const void *plain, uint32_t plain_len,
                        void *cipher, uint32_t *cipher_len);

/* Decrypt cipher_len bytes (includes tag).
 * plain must hold cipher_len - STM_CRYPTO_TAG_LEN. */
int  stm_crypto_decrypt(struct stm_crypto *ctx, uint64_t block_addr,
                        const void *cipher, uint32_t cipher_len,
                        void *plain, uint32_t *plain_len);

void stm_crypto_free(struct stm_crypto *ctx);

/* Argon2id: derive 32-byte key from passphrase + 16-byte salt. */
int  stm_crypto_derive_key(const char *pass, size_t pass_len,
                           const uint8_t *salt,
                           uint8_t *key_out);

/* Wrap DEK with KEK (XChaCha20-Poly1305). Generates random nonce. */
int  stm_crypto_wrap_key(const uint8_t *kek, const uint8_t *dek,
                         uint8_t *wrapped, uint8_t *nonce_out);

/* Unwrap DEK with KEK. */
int  stm_crypto_unwrap_key(const uint8_t *kek,
                           const uint8_t *wrapped, const uint8_t *nonce,
                           uint8_t *dek_out);

/* Cryptographic random bytes. */
void stm_crypto_random(void *buf, size_t len);

#endif /* STM_CRYPTO_H */
