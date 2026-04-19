#ifndef STM_CRYPTO_H
#define STM_CRYPTO_H

#include "stratum/types.h"

#define STM_CRYPTO_KEY_LEN    32
#define STM_CRYPTO_NONCE_LEN  24
#define STM_CRYPTO_TAG_LEN    16
#define STM_CRYPTO_SALT_LEN   16

/* Associated-data magic constants. Bound into the AEAD tag as AD so an
 * attacker can't silently swap a ciphertext between contexts that share
 * the same (paddr, write_gen) nonce. */
#define STM_AD_MAGIC_EXTENT   0x44545845u  /* 'EXTD' — file-data extent */
#define STM_AD_MAGIC_NODE     0x444E5442u  /* 'BTND' — btree node       */

/* Tree identity, bound into btree node AD. A tree_id=0 means "unscoped"
 * (e.g. unit tests that skip the fs mount layer). Production trees get
 * distinct ids so a node from the snap tree can't be smuggled into the
 * main tree via bptr rewrite even if both share the same DEK. */
#define STM_TREE_ID_NONE      0
#define STM_TREE_ID_MAIN      1
#define STM_TREE_ID_SNAP      2
#define STM_TREE_ID_SAVED     3  /* per-snapshot saved subtree (rollback read) */

/* AD for a file-data extent. Bound at encrypt time so a re-aimed extent
 * record (same ciphertext, different btree key) fails AEAD on read. */
struct __attribute__((packed)) stm_ad_extent {
    le32 ad_magic;     /* STM_AD_MAGIC_EXTENT */
    le32 ad_version;   /* 1 */
    le64 ad_ino;       /* owning inode */
    le64 ad_offset;    /* extent offset within file */
};

/* AD for a btree node. Binds tree identity so cross-tree node swaps fail. */
struct __attribute__((packed)) stm_ad_node {
    le32 ad_magic;     /* STM_AD_MAGIC_NODE */
    le32 ad_version;   /* 1 */
    le32 ad_tree_id;   /* STM_TREE_ID_* */
    le32 ad_reserved;  /* zero */
};

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
 * alongside the ciphertext to reproduce `write_gen` at decrypt.
 *
 * `ad` / `ad_len` bind context to the AEAD tag. Pass NULL / 0 for
 * legacy empty-AD mode (only remaining user: the tests' direct-API
 * tier that doesn't care about context binding). */
int  stm_crypto_encrypt(struct stm_crypto *ctx,
                        uint64_t block_addr, uint64_t write_gen,
                        const void *ad, uint32_t ad_len,
                        const void *plain, uint32_t plain_len,
                        void *cipher, uint32_t *cipher_len);

/* Decrypt cipher_len bytes (includes tag).
 * plain must hold cipher_len - STM_CRYPTO_TAG_LEN.
 * Both block_addr and write_gen must match what was used at encrypt,
 * and `ad` / `ad_len` must be byte-identical to the encrypt-time AD. */
int  stm_crypto_decrypt(struct stm_crypto *ctx,
                        uint64_t block_addr, uint64_t write_gen,
                        const void *ad, uint32_t ad_len,
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
