/* SPDX-License-Identifier: ISC */
/*
 * fs_pool — CF-2a: the per-connection 9P dispatch pool (stratumd-
 * internal; see docs/cf-2-design.md §3).
 *
 * One READER thread (the caller of stm_fs_pool_serve — the SWISS-4g
 * per-connection thread) reads frames off the byte stream, admits them
 * into a 64-slot bounded queue, and handles Tflush / Tversion / refused
 * Tattach inline. N WORKER threads execute stm_9p_server_handle with
 * per-worker response buffers; replies serialize through a per-
 * connection writer mutex (one write_full per frame — frames are
 * atomic units on the stream).
 *
 * This header is internal to src/cmd/stratumd (the engine_internal.h
 * precedent: tests may include it directly; it is NOT installed).
 */
#ifndef STRATUM_V2_STRATUMD_FS_POOL_H
#define STRATUM_V2_STRATUMD_FS_POOL_H

#include <stratum/9p.h>
#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct stm_ds_policy_table;

/* Slot count per connection. The Thylacine kernel client's tag window
 * is 64 — a deeper queue buys memory, not throughput. Also the total
 * in-flight bound (queued + executing + replying <= SLOTS). */
#define STM_FS_POOL_SLOTS        64u

/* Worker-count clamp + the auto default. Auto is 4 FLAT, not
 * ncpu-probed: in-VM musl sysconf(_SC_NPROCESSORS_ONLN) has no
 * substrate and would report 1 (docs/cf-2-design.md §3.6); the default
 * is serial (pool opt-in via --fs-workers >= 2, user-decided
 * 2026-07-07), so the deployment states its worker count explicitly. */
#define STM_FS_POOL_WORKERS_MAX  16u

/* Test-only hooks (NULL in production). pre_handle fires after an op is
 * committed for execution and before stm_9p_server_handle — on a WORKER
 * thread for a dispatched op, on the READER thread for an op the
 * RC-4b adaptive path executes inline — so a test can park there
 * (semaphore / sleep) to make "Tflush of an EXECUTING op" and
 * worker-overlap deterministic. A test that parks MUST also install
 * force_dispatch (below): a parked inline op parks the READER, so a
 * subsequently-sent Tflush is never read off the socket and the test
 * hangs. on_fatal fires (under the pool mutex) when the connection
 * FIRST latches dead, with the fatal rc — a test that provokes a fatal
 * while holding an op parked orders its release strictly after the
 * latch. Without that ordering, the release races the reader's
 * processing of the offending frame, and the losing interleave turns
 * the intended violation into a LEGAL one (the duplicate_tag_fatal
 * hang: the parked op completed into REPLYING first, so the dup was
 * admitted as legal tag reuse per the F2 rule and the connection never
 * died — the test's drain-to-EOF then blocked forever).
 * force_dispatch (RC-4b): consulted at admission UNDER the pool mutex
 * (must not block, must not re-enter the pool); non-NULL + returning
 * true suppresses the inline fast path for that op, forcing worker
 * dispatch — how the parking tests keep their parked ops on worker
 * threads, and how the depth>=2 arm is driven deterministically. */
typedef struct stm_fs_pool_test_hooks {
    void (*pre_handle)(void *arg, uint16_t tag, uint8_t type);
    void (*on_fatal)(void *arg, stm_status rc);
    bool (*force_dispatch)(void *arg);
    void  *arg;
} stm_fs_pool_test_hooks;

void stm_fs_pool_set_test_hooks(const stm_fs_pool_test_hooks *hooks);

/* Serve one connection with `workers` (>= 2) worker threads until EOF
 * or a fatal error. The caller owns fd + srv (this function closes
 * neither — mirroring the serial loop's structure where serve_client
 * does the teardown). peer_uid + user_policy feed the pre-dispatch
 * Tattach gate (TLY-A2-impl-1), exactly as the serial loop applies it.
 *
 * Returns STM_OK on clean client EOF (queued work drained, replies
 * delivered), STM_EIO / STM_EPROTOCOL / handler-fatal rc otherwise.
 */
stm_status stm_fs_pool_serve(int fd, stm_9p_server *srv,
                               uint32_t workers,
                               uid_t peer_uid,
                               const struct stm_ds_policy_table *user_policy);

/* Shared stratumd io helpers (defined in serve.c; the pool reuses them
 * so frame io has exactly one implementation). read_full returns 0 on
 * success, +1 on clean EOF before any byte, -errno otherwise (EINTR
 * retried; EAGAIN surfaced — the SO_RCVTIMEO idle path). */
int      stratumd_read_full(int fd, void *buf, size_t len);
int      stratumd_write_full(int fd, const void *buf, size_t len);
uint32_t stratumd_decode_le32(const uint8_t *p);
bool     stratumd_check_tattach(const uint8_t *req, uint32_t req_len,
                                  uid_t peer_uid,
                                  const struct stm_ds_policy_table *policy,
                                  uint8_t *resp, uint32_t resp_cap,
                                  uint32_t *resp_len);

#endif /* STRATUM_V2_STRATUMD_FS_POOL_H */
