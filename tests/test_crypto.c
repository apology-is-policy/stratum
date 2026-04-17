#include "test_main.h"
#include "stratum/crypto.h"
#include "stratum/fs.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_crypto.img";
static void cleanup(void) { unlink(img); }

/* ── low-level encrypt/decrypt round-trip ───────────────────────────── */

STM_TEST(test_crypto_roundtrip)
{
#ifndef STM_HAVE_CRYPTO
    printf("  %-50s SKIP (libsodium not available)\n", "crypto_roundtrip");
    return;
#else
    uint8_t key[STM_CRYPTO_KEY_LEN];
    struct stm_crypto *ctx = NULL;
    uint8_t plain[128], cipher[128 + STM_CRYPTO_TAG_LEN], back[128];
    uint32_t clen, plen, i;

    stm_crypto_random(key, sizeof(key));
    int rc = stm_crypto_init(key, &ctx);
    STM_ASSERT_EQ(rc, 0);

    for (i = 0; i < 128; i++) plain[i] = (uint8_t)i;

    rc = stm_crypto_encrypt(ctx, 42, 7, plain, 128, cipher, &clen);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(clen, 128u + STM_CRYPTO_TAG_LEN);

    rc = stm_crypto_decrypt(ctx, 42, 7, cipher, clen, back, &plen);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(plen, 128u);
    STM_ASSERT_MEM_EQ(plain, back, 128);

    /* wrong paddr should fail */
    rc = stm_crypto_decrypt(ctx, 99, 7, cipher, clen, back, &plen);
    STM_ASSERT_EQ(rc, -EIO);

    /* wrong write_gen should fail */
    rc = stm_crypto_decrypt(ctx, 42, 8, cipher, clen, back, &plen);
    STM_ASSERT_EQ(rc, -EIO);

    /* different write_gen at same paddr must yield different ciphertext
     * (this is the whole reason write_gen is in the nonce) */
    uint8_t cipher2[128 + STM_CRYPTO_TAG_LEN];
    uint32_t clen2;
    rc = stm_crypto_encrypt(ctx, 42, 8, plain, 128, cipher2, &clen2);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(clen, clen2);
    STM_ASSERT(memcmp(cipher, cipher2, clen) != 0);

    stm_crypto_free(ctx);
#endif
}

/* ── key derivation + wrap/unwrap ───────────────────────────────────── */

STM_TEST(test_crypto_key_wrap)
{
#ifndef STM_HAVE_CRYPTO
    printf("  %-50s SKIP\n", "key_wrap");
    return;
#else
    uint8_t salt[STM_CRYPTO_SALT_LEN], kek[STM_CRYPTO_KEY_LEN];
    uint8_t dek[STM_CRYPTO_KEY_LEN], dek_back[STM_CRYPTO_KEY_LEN];
    uint8_t wrapped[STM_CRYPTO_KEY_LEN + STM_CRYPTO_TAG_LEN];
    uint8_t nonce[STM_CRYPTO_NONCE_LEN];

    stm_crypto_random(salt, sizeof(salt));
    stm_crypto_random(dek, sizeof(dek));

    int rc = stm_crypto_derive_key("test-pass", 9, salt, kek);
    STM_ASSERT_EQ(rc, 0);

    rc = stm_crypto_wrap_key(kek, dek, wrapped, nonce);
    STM_ASSERT_EQ(rc, 0);

    rc = stm_crypto_unwrap_key(kek, wrapped, nonce, dek_back);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(dek, dek_back, STM_CRYPTO_KEY_LEN);

    /* wrong passphrase should fail unwrap */
    uint8_t bad_kek[STM_CRYPTO_KEY_LEN];
    rc = stm_crypto_derive_key("wrong-pass", 10, salt, bad_kek);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_crypto_unwrap_key(bad_kek, wrapped, nonce, dek_back);
    STM_ASSERT_EQ(rc, -EACCES);
#endif
}

/* ── encrypted filesystem: create, write, sync, reopen, read ────────── */

STM_TEST(test_encrypted_fs)
{
#ifndef STM_HAVE_CRYPTO
    printf("  %-50s SKIP\n", "encrypted_fs");
    return;
#else
    const char *pass = "stratum-secret";

    int rc = stm_fs_create(img, 64 * 1024 * 1024, pass);
    STM_ASSERT_EQ(rc, 0);

    {
        struct stm_fs *fs;
        rc = stm_fs_open(img, pass, &fs);
        STM_ASSERT_EQ(rc, 0);

        uint64_t ino;
        rc = stm_fs_create_file(fs, STM_ROOT_INO, "secret.txt", 0600, &ino);
        STM_ASSERT_EQ(rc, 0);
        rc = stm_fs_write(fs, ino, 0, "classified data", 15);
        STM_ASSERT_EQ(rc, 0);

        rc = stm_fs_sync(fs);
        STM_ASSERT_EQ(rc, 0);
        stm_fs_close(fs);
    }

    /* reopen with correct passphrase */
    {
        struct stm_fs *fs;
        rc = stm_fs_open(img, pass, &fs);
        STM_ASSERT_EQ(rc, 0);

        uint64_t ino;
        rc = stm_fs_lookup(fs, STM_ROOT_INO, "secret.txt", &ino);
        STM_ASSERT_EQ(rc, 0);

        char buf[64] = {0};
        uint32_t nread;
        rc = stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(nread, 15u);
        STM_ASSERT_MEM_EQ(buf, "classified data", 15);

        stm_fs_close(fs);
    }

    /* wrong passphrase should fail */
    {
        struct stm_fs *fs;
        rc = stm_fs_open(img, "wrong-password", &fs);
        STM_ASSERT_EQ(rc, -EACCES);
    }

    /* no passphrase on encrypted volume should fail */
    {
        struct stm_fs *fs;
        rc = stm_fs_open(img, NULL, &fs);
        STM_ASSERT_EQ(rc, -EACCES);
    }

    cleanup();
#endif
}

int main(void)
{
    STM_SUITE("crypto");
    STM_RUN(test_crypto_roundtrip);
    STM_RUN(test_crypto_key_wrap);
    STM_RUN(test_encrypted_fs);
    printf("all passed\n");
    return 0;
}
