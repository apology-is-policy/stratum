/* SPDX-License-Identifier: ISC */
/*
 * Tests for the SWISS-4m passphrase-encrypted keyfile (KFP1) format.
 *
 * Coverage:
 *   - generate → load(correct) roundtrips PK/SK exactly
 *   - load(wrong-passphrase) → STM_EBADTAG (AEAD authentication fails)
 *   - load(plaintext-keyfile) of an encrypted file → STM_EBADVERSION
 *   - load_passphrase of a plaintext-v1 keyfile → STM_EBADVERSION
 *   - tampered ciphertext byte → STM_EBADTAG (integrity check)
 */

#include "tharness.h"

#include <stratum/keyfile.h>
#include <stratum/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *TMP = "/tmp/stratum-keyfile-passphrase-test.bin";

STM_TEST(kfp1_generate_load_roundtrip)
{
    unlink(TMP);
    const char *pass = "correct horse battery staple";
    size_t plen = strlen(pass);

    STM_ASSERT_OK(stm_keyfile_generate_passphrase(TMP, pass, plen));

    stm_hybrid_keys k1 = {0};
    STM_ASSERT_OK(stm_keyfile_load_passphrase(TMP, pass, plen, &k1));

    /* Idempotent re-load gives identical PK/SK. */
    stm_hybrid_keys k2 = {0};
    STM_ASSERT_OK(stm_keyfile_load_passphrase(TMP, pass, plen, &k2));
    STM_ASSERT_EQ(memcmp(k1.pk, k2.pk, sizeof k1.pk), 0);
    STM_ASSERT_EQ(memcmp(k1.sk, k2.sk, sizeof k1.sk), 0);

    stm_hybrid_keys_wipe(&k1);
    stm_hybrid_keys_wipe(&k2);
    unlink(TMP);
}

STM_TEST(kfp1_wrong_passphrase_returns_ebadtag)
{
    unlink(TMP);
    const char *pass  = "correct horse battery staple";
    const char *wrong = "wrong passphrase";

    STM_ASSERT_OK(stm_keyfile_generate_passphrase(TMP, pass, strlen(pass)));

    stm_hybrid_keys k = {0};
    stm_status s = stm_keyfile_load_passphrase(TMP, wrong, strlen(wrong), &k);
    STM_ASSERT_EQ(s, STM_EBADTAG);

    /* Verify out param wasn't touched (still zero). */
    uint8_t zeros[STM_HYBRID_PK_LEN] = {0};
    STM_ASSERT_EQ(memcmp(k.pk, zeros, sizeof zeros), 0);

    unlink(TMP);
}

STM_TEST(kfp1_plain_load_rejects_encrypted)
{
    /* A plaintext loader (stm_keyfile_load) should refuse a KFP1
     * file with STM_EBADVERSION — not silently mis-parse. */
    unlink(TMP);
    const char *pass = "x";
    STM_ASSERT_OK(stm_keyfile_generate_passphrase(TMP, pass, 1));

    stm_hybrid_keys k = {0};
    stm_status s = stm_keyfile_load(TMP, &k);
    STM_ASSERT_EQ(s, STM_EBADVERSION);

    unlink(TMP);
}

STM_TEST(kfp1_passphrase_load_rejects_plain)
{
    /* The passphrase loader should refuse a plain v1 keyfile — caller
     * should fall back to stm_keyfile_load (or surface a clear error). */
    unlink(TMP);
    STM_ASSERT_OK(stm_keyfile_generate(TMP));

    stm_hybrid_keys k = {0};
    stm_status s = stm_keyfile_load_passphrase(TMP, "anything", 8, &k);
    STM_ASSERT_EQ(s, STM_EBADVERSION);

    unlink(TMP);
}

STM_TEST(kfp1_tampered_ciphertext_returns_ebadtag)
{
    unlink(TMP);
    const char *pass = "test123";
    STM_ASSERT_OK(stm_keyfile_generate_passphrase(TMP, pass, strlen(pass)));

    /* Flip a byte in the ciphertext region (header is the first 72
     * bytes; ciphertext starts at offset 72). */
    int fd = open(TMP, O_RDWR);
    STM_ASSERT(fd >= 0);
    uint8_t b = 0;
    STM_ASSERT_EQ(pread(fd, &b, 1, 200), 1);
    b ^= 0x01;
    STM_ASSERT_EQ(pwrite(fd, &b, 1, 200), 1);
    close(fd);

    stm_hybrid_keys k = {0};
    stm_status s = stm_keyfile_load_passphrase(TMP, pass, strlen(pass), &k);
    STM_ASSERT_EQ(s, STM_EBADTAG);

    unlink(TMP);
}

STM_TEST_MAIN("keyfile_passphrase")
