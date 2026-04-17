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
 *
 * The 24-byte XChaCha20-Poly1305 nonce is constructed as
 *     nonce = block_addr_le64 || write_gen_le64 || 8 zero bytes
 *
 * Both inputs matter: block_addr alone is NOT unique across COW
 * reallocation (the same paddr can be freed and handed back to a
 * later write), which would cause (key, nonce) reuse with different
 * plaintexts and catastrophic loss of confidentiality. write_gen is
 * a per-write counter supplied by the caller — usually `fs->gen` or
 * the btree node's `gen`. The caller must persist enough state
 * alongside the ciphertext to reproduce `write_gen` at decrypt. */
int  stm_crypto_encrypt(struct stm_crypto *ctx,
                        uint64_t block_addr, uint64_t write_gen,
                        const void *plain, uint32_t plain_len,
                        void *cipher, uint32_t *cipher_len);

/* Decrypt cipher_len bytes (includes tag).
 * plain must hold cipher_len - STM_CRYPTO_TAG_LEN.
 * Both block_addr and write_gen must match what was used at encrypt. */
int  stm_crypto_decrypt(struct stm_crypto *ctx,
                        uint64_t block_addr, uint64_t write_gen,
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
