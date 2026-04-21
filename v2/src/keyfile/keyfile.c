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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    if ((uint64_t)st.st_size != (uint64_t)STM_KEYFILE_SIZE) {
        close(fd);
        return STM_ERANGE;
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
