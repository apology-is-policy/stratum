/* SPDX-License-Identifier: ISC */
/*
 * Keyfile backend — MVP wrap-key storage (Phase 4 chunk P4-4a).
 *
 *   see include/stratum/keyfile.h for the surface + wire format.
 *
 * Stays deliberately small — janus replaces this layer in P4-4b
 * with a process-boundary-protected agent. The keyfile path here
 * continues as the "file" backend from ARCH §7.9.3's list.
 */

#include <stratum/keyfile.h>
#include <stratum/crypto.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Forward decls — used by both keyfile loaders below. */
static int read_full(int fd, uint8_t *buf, size_t len);
static int write_full(int fd, const uint8_t *buf, size_t len);

static void pack_u32_le(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v      );
    out[1] = (uint8_t)(v >>  8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

static uint32_t load_u32_le(const uint8_t in[4])
{
    return (uint32_t)in[0]
         | ((uint32_t)in[1] <<  8)
         | ((uint32_t)in[2] << 16)
         | ((uint32_t)in[3] << 24);
}

stm_status stm_keyfile_generate(const char *path)
{
    if (!path) return STM_EINVAL;
    stm_status s = stm_crypto_init();
    if (s != STM_OK) return s;

    stm_hybrid_keys kp;
    s = stm_hybrid_keygen(kp.pk, kp.sk);
    if (s != STM_OK) return s;

    uint8_t buf[STM_KEYFILE_SIZE];
    uint8_t magic_bytes[4];
    uint8_t ver_bytes[4];
    pack_u32_le(STM_KEYFILE_MAGIC,    magic_bytes);
    pack_u32_le(STM_KEYFILE_VERSION,  ver_bytes);
    memcpy(buf + 0, magic_bytes, 4);
    memcpy(buf + 4, ver_bytes,   4);
    memcpy(buf + 8,                              kp.pk, STM_HYBRID_PK_LEN);
    memcpy(buf + 8 + STM_HYBRID_PK_LEN,          kp.sk, STM_HYBRID_SK_LEN);

    /* Create the file mode 0600 — never group- or world-readable. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        stm_ct_memzero(buf, sizeof buf);
        stm_hybrid_keys_wipe(&kp);
        return STM_EBACKEND;
    }

    size_t written = 0;
    while (written < sizeof buf) {
        ssize_t n = write(fd, buf + written, sizeof buf - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            stm_ct_memzero(buf, sizeof buf);
            stm_hybrid_keys_wipe(&kp);
            return STM_EBACKEND;
        }
        written += (size_t)n;
    }
    if (fsync(fd) < 0) {
        close(fd);
        stm_ct_memzero(buf, sizeof buf);
        stm_hybrid_keys_wipe(&kp);
        return STM_EBACKEND;
    }
    close(fd);

    stm_ct_memzero(buf, sizeof buf);
    stm_hybrid_keys_wipe(&kp);
    return STM_OK;
}

stm_status stm_keyfile_load(const char *path, stm_hybrid_keys *out)
{
    if (!path || !out) return STM_EINVAL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return STM_ENOENT;

    /* R10 P2-4: reject keyfiles with trailing bytes. An exact
     * length check closes a "stash arbitrary data after the keys"
     * vector: attackers with write access could otherwise plant
     * provenance / audit-evasion markers in the trailing region,
     * and future backend versions might read those bytes by
     * accident. */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return STM_EBACKEND;
    }
    /* SWISS-4m: peek at the first 8 bytes to distinguish plaintext
     * v1 (KFIL) from passphrase-encrypted v2 (KFP1). If the file is
     * KFP1, return STM_EBADVERSION so callers know to use the
     * _passphrase variant. Otherwise size-check + parse as v1. */
    uint8_t header[8];
    if (read_full(fd, header, sizeof header) < 0) {
        close(fd);
        return STM_EBACKEND;
    }
    uint32_t peek_magic = load_u32_le(header);
    if (peek_magic == STM_KEYFILE_PASS_MAGIC) {
        close(fd);
        return STM_EBADVERSION;
    }
    if (peek_magic != STM_KEYFILE_MAGIC) {
        close(fd);
        return STM_EBADVERSION;
    }
    if ((uint64_t)st.st_size != (uint64_t)STM_KEYFILE_SIZE) {
        close(fd);
        return STM_ERANGE;
    }
    /* Rewind to read the rest in one go. */
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return STM_EBACKEND;
    }

    uint8_t buf[STM_KEYFILE_SIZE];
    size_t got = 0;
    while (got < sizeof buf) {
        ssize_t n = read(fd, buf + got, sizeof buf - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return STM_EBACKEND;
        }
        if (n == 0) {
            close(fd);
            stm_ct_memzero(buf, sizeof buf);
            return STM_ERANGE;    /* short file */
        }
        got += (size_t)n;
    }
    close(fd);

    uint32_t magic   = load_u32_le(buf + 0);
    uint32_t version = load_u32_le(buf + 4);
    if (magic   != STM_KEYFILE_MAGIC ||
        version != STM_KEYFILE_VERSION) {
        stm_ct_memzero(buf, sizeof buf);
        return STM_EBADVERSION;
    }

    memcpy(out->pk, buf + 8,                             STM_HYBRID_PK_LEN);
    memcpy(out->sk, buf + 8 + STM_HYBRID_PK_LEN,         STM_HYBRID_SK_LEN);
    stm_ct_memzero(buf, sizeof buf);
    return STM_OK;
}

void stm_hybrid_keys_wipe(stm_hybrid_keys *kp)
{
    if (!kp) return;
    stm_ct_memzero(kp->pk, sizeof kp->pk);
    stm_ct_memzero(kp->sk, sizeof kp->sk);
}

/* ────────────────────────────────────────────────────────────────────── */
/* SWISS-4m: passphrase-encrypted keyfile (KFP1 format).                  */
/* ────────────────────────────────────────────────────────────────────── */

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;   /* short file */
        off += (size_t)n;
    }
    return 0;
}

stm_status stm_keyfile_generate_passphrase(const char *path,
                                              const char *passphrase,
                                              size_t      pass_len)
{
    if (!path || !passphrase || pass_len == 0) return STM_EINVAL;

    stm_status s = stm_crypto_init();
    if (s != STM_OK) return s;

    /* Long-lived secret: a fresh hybrid keypair. The passphrase
     * doesn't *become* the secret — it merely wraps the secret. */
    stm_hybrid_keys kp;
    s = stm_hybrid_keygen(kp.pk, kp.sk);
    if (s != STM_OK) return s;

    /* CSPRNG salt + AEAD nonce. */
    uint8_t salt[16];
    uint8_t nonce[STM_AEAD_NONCE_LEN];
    stm_random_bytes(salt, sizeof salt);
    stm_random_bytes(nonce, sizeof nonce);

    stm_argon2id_params params = stm_argon2id_params_interactive(salt);
    stm_aead_mode mode = stm_aead_autodetect();
    size_t key_len = stm_aead_key_len(mode);
    if (key_len == 0 || key_len > STM_AEAD_KEY_LEN_MAX) {
        stm_hybrid_keys_wipe(&kp);
        return STM_EBACKEND;
    }

    /* KEK = Argon2id(passphrase, salt). Held in stack-frame memory;
     * memzero before scope exit. */
    uint8_t kek[STM_AEAD_KEY_LEN_MAX];
    s = stm_argon2id(&params, passphrase, pass_len, kek, key_len);
    if (s != STM_OK) {
        stm_ct_memzero(kek, sizeof kek);
        stm_hybrid_keys_wipe(&kp);
        return s;
    }

    /* AEAD-encrypt PK||SK as one blob. */
    uint8_t pt[STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN];
    memcpy(pt,                         kp.pk, STM_HYBRID_PK_LEN);
    memcpy(pt + STM_HYBRID_PK_LEN,     kp.sk, STM_HYBRID_SK_LEN);

    size_t tag_len = stm_aead_tag_len(mode);
    size_t ct_len_max = sizeof pt + tag_len;
    uint8_t *ct = malloc(ct_len_max);
    if (!ct) {
        stm_ct_memzero(kek, sizeof kek);
        stm_ct_memzero(pt, sizeof pt);
        stm_hybrid_keys_wipe(&kp);
        return STM_ENOMEM;
    }
    size_t ct_len = 0;
    s = stm_aead_encrypt(mode, kek, nonce, NULL, 0,
                            pt, sizeof pt,
                            ct, &ct_len);
    /* Wipe transient material as soon as it's no longer needed. */
    stm_ct_memzero(kek, sizeof kek);
    stm_ct_memzero(pt, sizeof pt);
    if (s != STM_OK) {
        stm_ct_memzero(ct, ct_len_max);
        free(ct);
        stm_hybrid_keys_wipe(&kp);
        return s;
    }

    /* Build the on-disk image: header (72 bytes) + ciphertext. */
    size_t total = STM_KEYFILE_PASS_HEADER_LEN + ct_len;
    uint8_t *buf = malloc(total);
    if (!buf) {
        stm_ct_memzero(ct, ct_len_max);
        free(ct);
        stm_hybrid_keys_wipe(&kp);
        return STM_ENOMEM;
    }
    pack_u32_le(STM_KEYFILE_PASS_MAGIC,    buf +  0);
    pack_u32_le(STM_KEYFILE_PASS_VERSION,  buf +  4);
    pack_u32_le(params.t_cost,             buf +  8);
    /* m_cost_kib is size_t in the params struct but bounded; pack as u32. */
    pack_u32_le((uint32_t)params.m_cost_kib, buf + 12);
    pack_u32_le(params.parallelism,        buf + 16);
    pack_u32_le((uint32_t)mode,            buf + 20);
    memcpy(buf + 24, salt,  sizeof salt);   /* 16 bytes -> [24,40) */
    memcpy(buf + 40, nonce, sizeof nonce);  /* 32 bytes -> [40,72) */
    memcpy(buf + 72, ct, ct_len);

    /* Wipe ct buffer before close — already on disk. */
    stm_ct_memzero(ct, ct_len_max);
    free(ct);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        stm_ct_memzero(buf, total);
        free(buf);
        stm_hybrid_keys_wipe(&kp);
        return STM_EBACKEND;
    }
    if (write_full(fd, buf, total) < 0 || fsync(fd) < 0) {
        close(fd);
        stm_ct_memzero(buf, total);
        free(buf);
        stm_hybrid_keys_wipe(&kp);
        return STM_EBACKEND;
    }
    close(fd);
    stm_ct_memzero(buf, total);
    free(buf);
    stm_hybrid_keys_wipe(&kp);
    return STM_OK;
}

stm_status stm_keyfile_load_passphrase(const char *path,
                                          const char *passphrase,
                                          size_t      pass_len,
                                          stm_hybrid_keys *out)
{
    if (!path || !passphrase || pass_len == 0 || !out) return STM_EINVAL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return STM_ENOENT;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return STM_EBACKEND;
    }
    /* File must be at least the header + minimum AEAD tag — bound
     * the ciphertext buffer up front. Compute the EXPECTED size from
     * the header's mode field after we read it. */
    if ((uint64_t)st.st_size < (uint64_t)STM_KEYFILE_PASS_HEADER_LEN) {
        close(fd);
        return STM_ERANGE;
    }
    /* Sanity cap — this format with our params doesn't exceed 8 KiB.
     * Reject anything implausibly large to bound malloc. */
    if ((uint64_t)st.st_size > (uint64_t)(STM_KEYFILE_PASS_HEADER_LEN
                                          + STM_HYBRID_PK_LEN
                                          + STM_HYBRID_SK_LEN
                                          + STM_AEAD_TAG_LEN_MAX
                                          + 1024)) {
        close(fd);
        return STM_ERANGE;
    }
    size_t total = (size_t)st.st_size;
    uint8_t *buf = malloc(total);
    if (!buf) { close(fd); return STM_ENOMEM; }
    if (read_full(fd, buf, total) < 0) {
        close(fd);
        free(buf);
        return STM_EBACKEND;
    }
    close(fd);

    uint32_t magic   = load_u32_le(buf +  0);
    uint32_t version = load_u32_le(buf +  4);
    if (magic != STM_KEYFILE_PASS_MAGIC ||
        version != STM_KEYFILE_PASS_VERSION) {
        stm_ct_memzero(buf, total);
        free(buf);
        return STM_EBADVERSION;
    }
    uint32_t t_cost      = load_u32_le(buf +  8);
    uint32_t m_cost_kib  = load_u32_le(buf + 12);
    uint32_t parallelism = load_u32_le(buf + 16);
    uint32_t mode_u32    = load_u32_le(buf + 20);

    /* Validate mode vs. what the build supports. */
    stm_aead_mode mode = (stm_aead_mode)mode_u32;
    if (mode != STM_AEAD_AEGIS256 && mode != STM_AEAD_XCHACHA20_SIV) {
        stm_ct_memzero(buf, total);
        free(buf);
        return STM_EBADVERSION;
    }
    size_t key_len = stm_aead_key_len(mode);
    size_t tag_len = stm_aead_tag_len(mode);
    size_t expected_ct_len = STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN + tag_len;
    if (total != STM_KEYFILE_PASS_HEADER_LEN + expected_ct_len) {
        stm_ct_memzero(buf, total);
        free(buf);
        return STM_ERANGE;
    }

    /* Bound KDF params: refuse anything outside libsodium's accepted
     * range so a malformed file can't cause an OOM during Argon2id. */
    if (t_cost < 1u || t_cost > 1000u ||
        m_cost_kib < 8u || m_cost_kib > (1u << 20) ||  /* up to 1 GiB */
        parallelism < 1u || parallelism > 1u) {
        stm_ct_memzero(buf, total);
        free(buf);
        return STM_EBADVERSION;
    }

    stm_argon2id_params params;
    params.t_cost      = t_cost;
    params.m_cost_kib  = m_cost_kib;
    params.parallelism = parallelism;
    memcpy(params.salt, buf + 24, 16);

    uint8_t kek[STM_AEAD_KEY_LEN_MAX];
    stm_status s = stm_argon2id(&params, passphrase, pass_len, kek, key_len);
    if (s != STM_OK) {
        stm_ct_memzero(buf, total);
        free(buf);
        stm_ct_memzero(kek, sizeof kek);
        return s;
    }

    uint8_t pt[STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN];
    size_t pt_len = 0;
    s = stm_aead_decrypt(mode, kek,
                            buf + 40,                /* nonce */
                            NULL, 0,
                            buf + 72, expected_ct_len,
                            pt, &pt_len);
    /* Wipe KEK before reporting status. */
    stm_ct_memzero(kek, sizeof kek);
    stm_ct_memzero(buf, total);
    free(buf);
    if (s != STM_OK) {
        stm_ct_memzero(pt, sizeof pt);
        /* STM_EBADTAG = wrong passphrase (most common case). */
        return s;
    }
    if (pt_len != STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN) {
        stm_ct_memzero(pt, sizeof pt);
        return STM_EPROTOCOL;
    }
    memcpy(out->pk, pt,                         STM_HYBRID_PK_LEN);
    memcpy(out->sk, pt + STM_HYBRID_PK_LEN,     STM_HYBRID_SK_LEN);
    stm_ct_memzero(pt, sizeof pt);
    return STM_OK;
}
