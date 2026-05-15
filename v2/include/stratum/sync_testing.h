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
 * TLY-A3-keyslot: insert a keyschema slot carrying a chosen
 * `wrapper` tag and an opaque `wrapped` blob, WITHOUT performing a
 * real cryptographic wrap. Persisted on the next stm_sync_commit.
 *
 * This seam exists because the mount-time UNWRAP-routing tests need
 * a pool that carries a STM_KS_WRAPPER_CORVUS slot, but the
 * production WRAP path that would produce a genuine corvus-sealed
 * blob does not exist yet — STRATUM-API-V1.md §5.2 specs only the
 * UNWRAP verb (the open bilateral question, thylacine-keyslot-design
 * §10). The blob is whatever bytes the caller supplies; a fake
 * corvus keyed by (dataset_id, key_id) maps it back to a DEK.
 *
 * The slot is inserted as CURRENT. The DEK is NOT added to the
 * in-RAM DEK map — the point of the test is that a subsequent
 * stm_sync_open rehydrates it via the wrapper-routed unwrap path.
 *
 * Returns STM_OK; STM_EINVAL on NULL/oversize args; propagates
 * keyschema-layer errors otherwise.
 */
STM_MUST_USE
stm_status stm_sync_keyschema_insert_for_test(stm_sync *s,
                                                uint64_t dataset_id,
                                                uint64_t key_id,
                                                stm_keyschema_wrapper wrapper,
                                                const void *wrapped,
                                                size_t wrapped_len);
#endif /* STRATUM_BUILD_TESTING_HOOKS */

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SYNC_TESTING_H */
