/* SPDX-License-Identifier: ISC */
/*
 * stm_sync — test-only accessors.
 *
 * This header exposes internal hooks useful ONLY for tests.
 * Production binaries have no legitimate reason to pierce these
 * abstractions; callers outside the test tree should not include
 * this header.
 *
 * P7-CAS-4b: tests need to override the FastCDC parameters used by
 * `stm_sync_migrate_to_cold`'s chunking pass. ARCH §6.9.4 defaults
 * (8 MiB avg / 2 MiB min / 32 MiB max) won't trigger sub-chunking
 * on the MVP recordsize cap (128 KiB) because every extent is
 * smaller than `min_size`. Tests override with small params (e.g.,
 * 16 KiB avg / 4 KiB min / 64 KiB max) to exercise multi-chunk
 * migrate behavior.
 *
 * The override is purely runtime; CDC params are not persisted on
 * disk (the same plaintext + same params yield identical
 * boundaries, so chunking is a stateless transformation). Any
 * future production "per-dataset CDC params" wiring will surface
 * a non-test API; this seam stays test-only.
 *
 * Gated behind `STRATUM_BUILD_TESTING_HOOKS` so production builds
 * cannot extern-declare the symbol — same containment posture as
 * `<stratum/snapshot_testing.h>`'s `stm_snapshot_create_for_test`.
 */
#ifndef STRATUM_V2_SYNC_TESTING_H
#define STRATUM_V2_SYNC_TESTING_H

#include <stratum/cdc.h>
#include <stratum/keyschema.h>
#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_sync;
typedef struct stm_sync stm_sync;

#ifdef STRATUM_BUILD_TESTING_HOOKS
/*
 * Override the sync handle's FastCDC chunker parameters. Validates
 * `params` via `stm_cdc_init` (same constraints as the public init
 * — min/avg/max ordering, mask popcounts, hardcap).
 *
 * Takes `s->lock` so concurrent migrate calls observe a consistent
 * snapshot of the cdc instance (cdc is read-only after init; the
 * setter atomically replaces the embedded struct under the lock).
 *
 * Returns STM_OK on success. STM_EINVAL if `s` or `params` are
 * NULL or `params` fails the validity check.
 */
STM_MUST_USE
stm_status stm_sync_set_cdc_params_for_test(stm_sync *s,
                                              const stm_cdc_params *params);

/*
 * Drop every decrypted-extent cache entry (takes s->lock).
 *
 * The extent WRITE path populates the cache (the plaintext is in hand
 * at write time), so a freshly-written extent's first read is served
 * from RAM. Tests that exercise the DISK read path — replica
 * fallback, corrupted-replica error surfacing, decrypt-on-read —
 * call this between the write and the read; without it those reads
 * never consult the device and pass (or fail) vacuously.
 */
void stm_sync_dcache_drain_for_test(stm_sync *s);

/*
 * TLY-A3-keyslot: insert a keyschema slot carrying a chosen
 * `wrapper` tag and an opaque `wrapped` blob, WITHOUT performing a
 * real cryptographic wrap. Persisted on the next stm_sync_commit.
 *
 * This seam injects a CORVUS (or any-wrapper) slot directly, with no
 * live corvus and no real cryptographic wrap. The production WRAP
 * path is `stm_sync_add_dataset_key_corvus` (TLY-A3-keyslot-wrap
 * chunk 5a) — but driving it needs a live corvus, so the
 * mount-failure-mode tests (no-corvus / corvus-rejects /
 * corvus-unreachable) stay on this seam: it stands up a pool carrying
 * a STM_KS_WRAPPER_CORVUS slot with a chosen opaque blob, which the
 * test then exercises against an absent or canned-DEK fake corvus.
 * The blob is whatever bytes the caller supplies.
 *
 * The slot is inserted as CURRENT. The DEK is NOT added to the
 * in-RAM DEK map — the point of the test is that a subsequent
 * stm_sync_open rehydrates it via the wrapper-routed unwrap path.
 *
 * Returns STM_OK; STM_EINVAL on NULL/oversize args; propagates
 * keyschema-layer errors otherwise.
 *
 * TLY-A3-keyslot-wrap: `corvus_dataset_path` follows the keyschema
 * rule — REQUIRED (non-NULL, 1..STM_KEYSCHEMA_CORVUS_PATH_MAX) for a
 * STM_KS_WRAPPER_CORVUS slot, absent (NULL, 0) for every other
 * wrapper. STM_EINVAL on violation. The mount-time UNWRAP reads the
 * stored path back from the slot, so a CORVUS test slot must supply
 * the path the fake corvus expects.
 */
STM_MUST_USE
stm_status stm_sync_keyschema_insert_for_test(stm_sync *s,
                                                uint64_t dataset_id,
                                                uint64_t key_id,
                                                stm_keyschema_wrapper wrapper,
                                                const void *wrapped,
                                                size_t wrapped_len,
                                                const char *corvus_dataset_path,
                                                size_t corvus_dataset_path_len);
#endif /* STRATUM_BUILD_TESTING_HOOKS */

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_TESTING_H */
