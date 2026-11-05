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

/* A link at a key's name would hand the key to whoever planted it. */
STM_TEST(keyfile_generate_refuses_a_link_at_its_name)
{
    char link_path[256], target[256];
    snprintf(link_path, sizeof link_path, "%s.link", TMP);
    snprintf(target, sizeof target, "%s.target", TMP);
    unlink(link_path);
    unlink(target);
    STM_ASSERT_EQ(symlink(target, link_path), 0);
    STM_ASSERT_EQ(stm_keyfile_generate(link_path), STM_EBACKEND);
    STM_ASSERT_EQ(stm_keyfile_generate_passphrase(link_path, "pw", 2), STM_EBACKEND);
    struct stat st;
    STM_ASSERT(lstat(target, &st) != 0);
    unlink(link_path);
}

/* A file found at the name is made private: open's mode reaches only a file it creates. */
STM_TEST(keyfile_generate_over_a_readable_file_makes_it_private)
{
    unlink(TMP);
    int fd = open(TMP, O_WRONLY | O_CREAT | O_EXCL, 0644);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_EQ(write(fd, "an older and longer file than a key", 35), 35);
    STM_ASSERT_EQ(fchmod(fd, 0644), 0);
    close(fd);
    STM_ASSERT_OK(stm_keyfile_generate(TMP));
    struct stat st;
    STM_ASSERT_EQ(stat(TMP, &st), 0);
    STM_ASSERT_EQ(st.st_mode & 0777, 0600);
    stm_hybrid_keys k = {0};
    STM_ASSERT_OK(stm_keyfile_load(TMP, &k));
    unlink(TMP);
}

/* What the caller made exclusively is what receives the key, in either form. */
STM_TEST(keyfile_generate_fd_writes_a_loadable_key)
{
    unlink(TMP);
    int fd = open(TMP, O_WRONLY | O_CREAT | O_EXCL, 0600);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_OK(stm_keyfile_generate_fd(fd));
    close(fd);
    stm_hybrid_keys k = {0};
    STM_ASSERT_OK(stm_keyfile_load(TMP, &k));
    unlink(TMP);
    fd = open(TMP, O_WRONLY | O_CREAT | O_EXCL, 0600);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_OK(stm_keyfile_generate_passphrase_fd(fd, "pw", 2));
    close(fd);
    STM_ASSERT_OK(stm_keyfile_load_passphrase(TMP, "pw", 2, &k));
    unlink(TMP);
}

STM_TEST_MAIN("keyfile_passphrase")
