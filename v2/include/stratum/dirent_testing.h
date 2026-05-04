/* SPDX-License-Identifier: ISC */
/*
 * stm_dirent — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests.
 * Production binaries have no legitimate reason to pierce these
 * abstractions; callers outside the test tree should not include
 * this header.
 *
 * P8-POSIX-9b R88 P2-1: closes the regression-test gap on
 * `stm_dirent_alloc`'s whiteout-preservation contract under
 * hash-colliding chain walks. The bug shape is: a whiteout slot
 * for one name gets silently overwritten when an alloc of a
 * different-named record's chain visits the whiteout's probe
 * (i.e., the names hash to within PROBE_MAX of each other). With
 * fnv1a64's 2^64 output space, finding such a collision via
 * short-ASCII brute force within MaxProbe=64 is statistically
 * infeasible (probability ~2^-58 per pair; 12M trial names yielded
 * zero collisions). To exercise the bug deterministically the test
 * needs to install a record at a CHOSEN probe — bypassing the
 * normal chain walk that derives probe = fnv1a64(name) + offset.
 * `stm_dirent_install_at_probe_for_test` does exactly that.
 *
 * Same gate convention as `<stratum/snapshot_testing.h>`: every
 * symbol in this header is behind the `STRATUM_BUILD_TESTING_HOOKS`
 * compile flag. The CMake test build sets it PUBLIC on the
 * underlying `stm_dirent` library so test sources see the
 * prototype AND the symbol exists in the linked archive. A
 * production build with `-DSTRATUM_BUILD_TESTING_HOOKS=OFF`
 * compiles neither prototype nor definition.
 */
#ifndef STRATUM_V2_DIRENT_TESTING_H
#define STRATUM_V2_DIRENT_TESTING_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_dirent_index;
typedef struct stm_dirent_index stm_dirent_index;

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Install (or overwrite) a record at the EXACT (dataset_id,
 * dir_ino, hash_probe) key, bypassing the chain walk that
 * stm_dirent_alloc / _whiteout / _unlink use. Production callers
 * MUST NOT use this — it lets a test construct slot configurations
 * (e.g., a whiteout for one name at the starting probe of a
 * DIFFERENT name's chain) that no normal API path can produce
 * directly.
 *
 * The flags + child_type + name fields are written verbatim. The
 * caller is responsible for shape consistency (e.g., live record:
 * name_len in [1,255] + child_type in valid DT_* set + flags = 0;
 * tombstone: name_len = 0 + flags = TOMBSTONE; whiteout: name_len
 * in [1,255] + child_type = STM_DT_WHITEOUT + flags = WHITEOUT).
 * The ON-DISK decoder will reject malformed combinations at next
 * mount; this writer doesn't validate at install time.
 *
 * Refusals:
 *   - NULL idx (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 *   - name_len > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - STM_ENOMEM if the records[] cap can't grow.
 */
STM_MUST_USE
stm_status stm_dirent_install_at_probe_for_test(
        stm_dirent_index *idx,
        uint64_t dataset_id, uint64_t dir_ino, uint64_t hash_probe,
        const uint8_t *name, uint8_t name_len,
        uint64_t child_ino, uint64_t child_gen,
        uint8_t child_type, uint8_t flags);

/*
 * Compute fnv1a64 over `name` using the same parameters as the
 * dirent.c chain walker (so a test can derive the chain's
 * starting probe for a given name without duplicating the
 * implementation's hash function).
 */
uint64_t stm_dirent_fnv1a64_for_test(const uint8_t *name, size_t len);
#endif /* STRATUM_BUILD_TESTING_HOOKS */

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_DIRENT_TESTING_H */
