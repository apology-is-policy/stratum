/* SPDX-License-Identifier: ISC */
/*
 * fs_pool — CF-2a: the per-connection 9P dispatch pool.
 *
 * Design: docs/cf-2-design.md §3 (invariants CF2-I1/I2/I4/I6/I8 live
 * here; CF2-I3/I5 are server.c's — CF-2b). Shape summary:
 *
 *   reader (caller thread)          workers (N threads)
 *   ──────────────────────          ───────────────────
 *   read frame                      pop slot (FIFO ring)
 *   Tversion  -> barrier + inline   [cancelled/dead -> discard]
 *   Tflush    -> cancel/wait+Rflush stm_9p_server_handle
 *   Tattach   -> policy gate        [flush_pending -> discard reply]
 *   else      -> admit to a slot    write reply under write_mu
 *                (bounded: 64 slots mark slot FREE + broadcast
 *                + queued-bytes budget)
 *
 * The slot table doubles as the in-flight registry (Tflush's lookup
 * domain). Exactly one wire reply per admitted request UNLESS flushed
 * before its reply was started (then exactly zero) or the connection
 * latches dead (CF2-I1). Rflush is written only after the flushed
 * request's reply is sent or permanently discarded (CF2-I2).
 *
 * Locking: pool.mu guards every slot/ring/counter field; write_mu
 * serializes frame writes. Never nested (mu is always released before
 * taking write_mu). Workers broadcast slot_cv on every completion —
 * the reader waits there for admission space, flush completion, and
 * the Tversion barrier; work_cv wakes workers on admission/teardown.
 *
 * Every handler is finite-duration (stm_fs_lock is non-blocking), so
 * every wait here terminates once the in-flight ops complete.
 */

#include "fs_pool.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Test hooks.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

static stm_fs_pool_test_hooks g_test_hooks; /* zero-init: no hooks */

void stm_fs_pool_set_test_hooks(const stm_fs_pool_test_hooks *hooks)
{
    if (hooks) g_test_hooks = *hooks;
    else       memset(&g_test_hooks, 0, sizeof g_test_hooks);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Types.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

typedef enum {
    SLOT_FREE = 0,
    SLOT_QUEUED,        /* admitted, waiting for a worker */
    SLOT_EXECUTING,     /* a worker is inside stm_9p_server_handle */
    SLOT_REPLYING,      /* reply committed, write in flight. The TAG is
                         * already retired (admission ignores REPLYING —
                         * the kernel client reuses tag 0 the instant a
                         * reply lands, faster than the worker re-locks)
                         * but a Tflush still finds it and WAITS, so
                         * Rflush stays ordered after the reply (CF2-I2). */
} slot_state;

typedef struct {
    slot_state state;
    bool       cancelled;       /* Tflush hit it while QUEUED */
    bool       flush_pending;   /* Tflush hit it while EXECUTING */
    uint16_t   tag;
    uint8_t    type;
    uint8_t   *req;             /* heap frame, exact wire size */
    uint32_t   req_len;
} pool_slot;

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  work_cv;    /* workers: queue non-empty / teardown */
    pthread_cond_t  slot_cv;    /* reader: completion / space / barrier */

    pool_slot slots[STM_FS_POOL_SLOTS];
    uint16_t  ring[STM_FS_POOL_SLOTS];  /* FIFO of slot indices */
    uint32_t  ring_head;                /* dequeue point */
    uint32_t  n_queued;                 /* ring occupancy */
    uint32_t  n_inflight;               /* slots not FREE */
    size_t    queued_bytes;             /* sum req_len over QUEUED slots */

    bool       draining;   /* no more admissions; drain queue, then exit */
    bool       dead;       /* fatal latch: abandon queued, skip replies */
    stm_status fatal_rc;   /* first fatal status (returned by serve) */

    /* Stable after init. */
    int             fd;
    stm_9p_server  *srv;
    pthread_mutex_t write_mu;

    /* Reader-owned msize mirror. s->msize mutates ONLY under the
     * Tversion barrier (all workers idle, reader executing h_version
     * inline), so the reader republishes it here under mu afterward;
     * workers size their resp buffers from it at pop time. */
    uint32_t resp_need;
} fs_pool;

static inline void pool_lock(fs_pool *p)   {
    if (pthread_mutex_lock(&p->mu) != 0) abort();
}
static inline void pool_unlock(fs_pool *p) {
    if (pthread_mutex_unlock(&p->mu) != 0) abort();
}

/* Queued-bytes budget: big frames throttle to depth ~4; small-op
 * pipelining is slot-capped long before this bites. A single frame
 * always fits (frame <= msize <= 4 x msize <= budget). */
static inline size_t pool_byte_budget(uint32_t msize)
{
    size_t b = 4u * (size_t)msize;
    return b < (1u << 20) ? (1u << 20) : b;
}

/* Latch the connection dead (first fatal status wins) and wake both
 * sides. Caller holds mu. */
static void pool_latch_dead_locked(fs_pool *p, stm_status rc)
{
    if (!p->dead) {
        p->dead     = true;
        p->fatal_rc = rc;
        if (g_test_hooks.on_fatal)
            g_test_hooks.on_fatal(g_test_hooks.arg, rc);
    }
    pthread_cond_broadcast(&p->work_cv);
    pthread_cond_broadcast(&p->slot_cv);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Worker.                                                                */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    fs_pool  *pool;
    pthread_t tid;
} pool_worker_handle;

static void *pool_worker_main(void *arg)
{
    fs_pool *p = arg;

    /* Fatal-signal mask is inherited from the spawning reader thread
     * (the SWISS-4g connection worker already blocks INT/TERM/HUP/
     * QUIT) — POSIX guarantees pthread mask inheritance. */

    uint8_t *resp     = NULL;
    uint32_t resp_cap = 0;

    pool_lock(p);
    for (;;) {
        while (p->n_queued == 0 && !p->draining && !p->dead)
            pthread_cond_wait(&p->work_cv, &p->mu);
        if (p->n_queued == 0) break;   /* draining/dead + empty: exit */

        uint16_t   idx = p->ring[p->ring_head % STM_FS_POOL_SLOTS];
        pool_slot *sl  = &p->slots[idx];
        p->ring_head++;
        p->n_queued--;
        p->queued_bytes -= sl->req_len;

        if (sl->cancelled || p->dead) {
            /* Flushed while queued (Rflush already sent — the op must
             * never execute, CF2-I2), or the connection died (abandon:
             * no execution, no reply). */
            free(sl->req);
            sl->req   = NULL;
            sl->state = SLOT_FREE;
            sl->cancelled = false;
            sl->flush_pending = false;
            p->n_inflight--;
            pthread_cond_broadcast(&p->slot_cv);
            continue;
        }

        sl->state = SLOT_EXECUTING;
        uint32_t need = p->resp_need;
        pool_unlock(p);

        if (resp_cap < need) {
            uint8_t *nr = realloc(resp, need);
            if (!nr) {
                /* Abandon the op unexecuted and latch the connection
                 * dead — the client would otherwise hang on the tag. */
                pool_lock(p);
                pool_latch_dead_locked(p, STM_ENOMEM);
                free(sl->req);
                sl->req   = NULL;
                sl->state = SLOT_FREE;
                sl->cancelled = false;
                sl->flush_pending = false;
                p->n_inflight--;
                pthread_cond_broadcast(&p->slot_cv);
                continue;   /* holding mu */
            }
            resp     = nr;
            resp_cap = need;
        }

        if (g_test_hooks.pre_handle)
            g_test_hooks.pre_handle(g_test_hooks.arg, sl->tag, sl->type);

        {
            uint32_t   rlen = 0;
            stm_status hrc  = stm_9p_server_handle(p->srv,
                                                     sl->req, sl->req_len,
                                                     resp, resp_cap,
                                                     &rlen);
            pool_lock(p);
            bool send = false;
            if (hrc != STM_OK || rlen == 0u) {
                /* Fatal per the handler contract — the serial loop
                 * closes the connection here; the pool latches dead. */
                pool_latch_dead_locked(
                    p, (hrc == STM_OK) ? STM_EPROTOCOL : hrc);
            } else {
                send = !sl->flush_pending && !p->dead;
                /* else: flushed while executing (reply discarded) or
                 * dead (peer gone) — the op completes reply-less. */
            }

            /* Retire the TAG before the reply write: state REPLYING is
             * invisible to the admission dup-check, so the kernel
             * client — whose tags are table indices, reusing tag 0 on
             * every synchronous op — can send its next same-tag
             * request the instant this reply lands, without racing
             * this worker's re-lock (the boot-gate F2 fix: pre-fix,
             * the reuse tripped the dup-tag gate and killed the
             * mount). The slot itself stays occupied through the
             * write so a Tflush can still find it and wait — Rflush
             * must be ordered after a committed reply (CF2-I2; the
             * naive retire-to-FREE variant let a not-found Rflush
             * race the in-flight reply to write_mu). */
            if (send) {
                sl->state = SLOT_REPLYING;
                pool_unlock(p);
                if (pthread_mutex_lock(&p->write_mu) != 0) abort();
                int wrc = stratumd_write_full(p->fd, resp, rlen);
                if (pthread_mutex_unlock(&p->write_mu) != 0) abort();
                pool_lock(p);
                if (wrc != 0)
                    pool_latch_dead_locked(p, STM_EIO);
            }
            free(sl->req);
            sl->req   = NULL;
            sl->state = SLOT_FREE;
            sl->cancelled = false;
            sl->flush_pending = false;
            p->n_inflight--;
            pthread_cond_broadcast(&p->slot_cv);
        }
        /* loop continues holding mu */
    }
    pool_unlock(p);

    free(resp);
    return NULL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Reader-side helpers.                                                   */
/* ────────────────────────────────────────────────────────────────────── */

/* Admission-side registry lookup: is this tag LIVE (would a new
 * request with it be a duplicate)? Caller holds mu. Two slot flavors
 * are deliberately NOT live even though their slots are occupied:
 *   - cancelled (flushed while QUEUED): its Rflush has been sent, so
 *     per 9P the client may reuse the tag immediately — before a
 *     worker pops + discards the corpse;
 *   - REPLYING: the reply is committed and (possibly already) on the
 *     wire, so a synchronous client legally sends its next same-tag
 *     request before the worker re-locks to free the slot (the kernel
 *     client reuses tag 0 on every op — the boot-gate F2 class).
 * Skipping both keeps legal reuse from tripping the duplicate gate. */
static pool_slot *pool_find_live_tag_locked(fs_pool *p, uint16_t tag)
{
    for (uint32_t i = 0; i < STM_FS_POOL_SLOTS; i++) {
        pool_slot *sl = &p->slots[i];
        if ((sl->state == SLOT_QUEUED || sl->state == SLOT_EXECUTING)
            && !sl->cancelled && sl->tag == tag)
            return sl;
    }
    return NULL;
}

/* Flush-side lookup: prefer a LIVE slot (the op the client most
 * plausibly means — under tag reuse the older incarnation is already
 * answered); fall back to a REPLYING one so the Rflush can be ordered
 * strictly after that reply's in-flight write (CF2-I2). */
static pool_slot *pool_find_flush_target_locked(fs_pool *p, uint16_t tag)
{
    pool_slot *live = pool_find_live_tag_locked(p, tag);
    if (live) return live;
    for (uint32_t i = 0; i < STM_FS_POOL_SLOTS; i++) {
        pool_slot *sl = &p->slots[i];
        if (sl->state == SLOT_REPLYING && sl->tag == tag) return sl;
    }
    return NULL;
}

static pool_slot *pool_find_free_locked(fs_pool *p)
{
    for (uint32_t i = 0; i < STM_FS_POOL_SLOTS; i++)
        if (p->slots[i].state == SLOT_FREE) return &p->slots[i];
    return NULL;
}

/* Read the 4-byte size header, idle-aware: an SO_RCVTIMEO expiry
 * (EAGAIN/EWOULDBLOCK) with ZERO bytes consumed and work still in
 * flight means the client is quietly waiting for a pipelined batch —
 * not idle — so retry. An expiry with the connection fully idle is a
 * real idle timeout (fatal, matching the serial loop). An expiry
 * MID-header is a stalled sender mid-frame — always fatal (a retry
 * could not resynchronize the stream). Returns 0 / +1 (clean EOF
 * before any byte) / -errno. */
static int pool_read_header(fs_pool *p, uint8_t *buf)
{
    size_t done = 0;
    while (done < 4u) {
        ssize_t n = read(p->fd, buf + done, 4u - done);
        if (n == 0)
            return (done == 0) ? 1 : -EPIPE;
        if (n < 0) {
            if (errno == EINTR) continue;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && done == 0) {
                bool busy;
                pool_lock(p);
                busy = (p->n_inflight > 0) && !p->dead;
                pool_unlock(p);
                if (busy) continue;
            }
            return -errno;
        }
        done += (size_t)n;
    }
    return 0;
}

/* RC-4b: is another frame (or part of one) already buffered on the
 * connection? The adaptive-dispatch depth signal MUST come from the
 * socket — the audit-F1 lesson: n_inflight alone self-starves, because
 * inline execution never raises it and the reader cannot read frames
 * while executing inline, so every op would inline forever and the
 * pool would degenerate to the serial loop at every depth. Buffered
 * bytes mean the client has pipelined: dispatch, and the burst
 * overlaps. Zero-timeout poll rather than ioctl(FIONREAD) — the guest
 * stratumd's AF_UNIX fd is a pouch srvconn stream where SYS_POLL is
 * wired and FIONREAD is not. POLLHUP/POLLERR also report "pending":
 * the dispatched op proceeds and the reader discovers EOF/error on its
 * next header read — the normal teardown path. A probe failure
 * reports "not pending" (fail toward inline == the serial-equivalent
 * behavior). */
static bool pool_socket_pending(int fd)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    return poll(&pfd, 1, 0) > 0;
}

/* Write an inline reply (Rflush / Rversion / refused-Tattach Rlerror)
 * from the reader. Returns 0 or -errno. */
static int pool_write_inline(fs_pool *p, const uint8_t *buf, uint32_t len)
{
    if (pthread_mutex_lock(&p->write_mu) != 0) abort();
    int rc = stratumd_write_full(p->fd, buf, len);
    if (pthread_mutex_unlock(&p->write_mu) != 0) abort();
    return rc;
}

/* Build the 7-byte Rflush frame. */
static void build_rflush(uint8_t *out, uint16_t tag)
{
    out[0] = 7; out[1] = 0; out[2] = 0; out[3] = 0;
    out[4] = STM_9P_RFLUSH;
    out[5] = (uint8_t)(tag & 0xFFu);
    out[6] = (uint8_t)((tag >> 8) & 0xFFu);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Inline op handling (reader thread).                                    */
/* ────────────────────────────────────────────────────────────────────── */

/* Tflush (CF2-I2). frame is the full Tflush message. Returns 0 on
 * success, -1 on a fatal condition (dead latched / write failed). */
static int pool_handle_flush(fs_pool *p, const uint8_t *frame,
                               uint32_t frame_len)
{
    uint16_t tag = (uint16_t)((uint16_t)frame[5] | ((uint16_t)frame[6] << 8));

    /* Tolerant parse, matching the serial h_flush (which ignores the
     * body entirely): a Tflush too short to carry oldtag cancels
     * nothing and still gets its Rflush. */
    bool have_oldtag = frame_len >= STM_9P_HDR_SIZE + 2u;
    uint16_t oldtag = 0;
    if (have_oldtag)
        oldtag = (uint16_t)((uint16_t)frame[7] | ((uint16_t)frame[8] << 8));

    pool_lock(p);
    if (have_oldtag) {
        pool_slot *sl = pool_find_flush_target_locked(p, oldtag);
        if (sl && sl->state == SLOT_QUEUED) {
            /* Never executes; a worker discards it on pop. Rflush may
             * go out immediately — the flushed op will never reply. */
            sl->cancelled = true;
        } else if (sl && sl->state == SLOT_EXECUTING) {
            /* Discard its reply, then wait for completion. */
            sl->flush_pending = true;
            while (sl->state != SLOT_FREE && !p->dead)
                pthread_cond_wait(&p->slot_cv, &p->mu);
        } else if (sl && sl->state == SLOT_REPLYING) {
            /* Too late to discard — the reply is committed and its
             * write is in flight. Wait for the slot to drain so the
             * Rflush below is ordered after it (CF2-I2). */
            while (sl->state != SLOT_FREE && !p->dead)
                pthread_cond_wait(&p->slot_cv, &p->mu);
        }
        /* NULL: already completed (a completed op's reply write is
         * ordered before this Rflush by write_mu) or never seen —
         * immediate Rflush either way. */
    }
    bool dead = p->dead;
    pool_unlock(p);
    if (dead) return -1;

    uint8_t rf[7];
    build_rflush(rf, tag);
    if (pool_write_inline(p, rf, sizeof rf) != 0) {
        pool_lock(p);
        pool_latch_dead_locked(p, STM_EIO);
        pool_unlock(p);
        return -1;
    }
    return 0;
}

/* Tversion (CF2-I4): quiesce — drain every in-flight op (they execute
 * and reply normally; a client pipelining ops concurrent with Tversion
 * has no ordering claim on them), then run h_version inline on the
 * reader (it clunks every fid + renegotiates msize with zero
 * concurrency), reply, and republish the msize mirror. Returns 0 or
 * -1 (fatal). */
static int pool_handle_version(fs_pool *p, const uint8_t *frame,
                                 uint32_t frame_len)
{
    pool_lock(p);
    while (p->n_inflight > 0 && !p->dead)
        pthread_cond_wait(&p->slot_cv, &p->mu);
    if (p->dead) {
        pool_unlock(p);
        return -1;
    }
    pool_unlock(p);

    /* Zero in-flight ops; workers are parked on work_cv. The reader is
     * the only thread touching srv. */
    uint8_t  vresp[256];
    uint32_t vlen = 0;
    stm_status hrc = stm_9p_server_handle(p->srv, frame, frame_len,
                                            vresp, sizeof vresp, &vlen);
    if (hrc != STM_OK || vlen == 0u) {
        pool_lock(p);
        pool_latch_dead_locked(p, (hrc == STM_OK) ? STM_EPROTOCOL : hrc);
        pool_unlock(p);
        return -1;
    }
    if (pool_write_inline(p, vresp, vlen) != 0) {
        pool_lock(p);
        pool_latch_dead_locked(p, STM_EIO);
        pool_unlock(p);
        return -1;
    }

    pool_lock(p);
    p->resp_need = stm_9p_server_msize(p->srv);
    pool_unlock(p);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* stm_fs_pool_serve.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_fs_pool_serve(int fd, stm_9p_server *srv,
                               uint32_t workers,
                               uid_t peer_uid,
                               const struct stm_ds_policy_table *user_policy)
{
    if (fd < 0 || !srv || workers < 2u) return STM_EINVAL;
    if (workers > STM_FS_POOL_WORKERS_MAX)
        workers = STM_FS_POOL_WORKERS_MAX;

    fs_pool *p = calloc(1, sizeof *p);
    if (!p) return STM_ENOMEM;

    p->fd        = fd;
    p->srv       = srv;
    p->resp_need = stm_9p_server_msize(srv);   /* MSIZE_MIN pre-Tversion */

    if (pthread_mutex_init(&p->mu, NULL) != 0) { free(p); return STM_ENOMEM; }
    if (pthread_cond_init(&p->work_cv, NULL) != 0) {
        pthread_mutex_destroy(&p->mu); free(p); return STM_ENOMEM;
    }
    if (pthread_cond_init(&p->slot_cv, NULL) != 0) {
        pthread_cond_destroy(&p->work_cv);
        pthread_mutex_destroy(&p->mu); free(p); return STM_ENOMEM;
    }
    if (pthread_mutex_init(&p->write_mu, NULL) != 0) {
        pthread_cond_destroy(&p->slot_cv);
        pthread_cond_destroy(&p->work_cv);
        pthread_mutex_destroy(&p->mu); free(p); return STM_ENOMEM;
    }

    pool_worker_handle *wh = calloc(workers, sizeof *wh);
    if (!wh) {
        pthread_mutex_destroy(&p->write_mu);
        pthread_cond_destroy(&p->slot_cv);
        pthread_cond_destroy(&p->work_cv);
        pthread_mutex_destroy(&p->mu); free(p); return STM_ENOMEM;
    }

    uint32_t n_started = 0;
    for (uint32_t i = 0; i < workers; i++) {
        wh[i].pool = p;
        if (pthread_create(&wh[i].tid, NULL, pool_worker_main, p) != 0)
            break;
        n_started++;
    }
    if (n_started == 0) {
        /* Could not start a single worker — no pool to run. */
        free(wh);
        pthread_mutex_destroy(&p->write_mu);
        pthread_cond_destroy(&p->slot_cv);
        pthread_cond_destroy(&p->work_cv);
        pthread_mutex_destroy(&p->mu);
        free(p);
        return STM_ENOMEM;
    }
    /* A partial pool (n_started < workers) serves correctly — the
     * worker count is a throughput knob, not a correctness one. */

    uint8_t hdr[4];
    uint8_t inline_resp[4096];
    bool    clean_eof = false;

    /* RC-4b adaptive dispatch: the reader-owned response buffer for
     * inline-executed data ops (grown to the msize mirror on demand —
     * a reply can be msize-sized, unlike the fixed-size Rflush /
     * Rversion / Rlerror the stack inline_resp serves). */
    uint8_t *ilr     = NULL;
    uint32_t ilr_cap = 0;

    for (;;) {
        pool_lock(p);
        bool dead = p->dead;
        pool_unlock(p);
        if (dead) break;

        int r = pool_read_header(p, hdr);
        if (r == 1) { clean_eof = true; break; }
        if (r != 0) {
            pool_lock(p);
            pool_latch_dead_locked(p, STM_EIO);
            pool_unlock(p);
            break;
        }

        uint32_t size = stratumd_decode_le32(hdr);

        /* Frame gate: the NEGOTIATED msize (spec-conformant; stricter
         * than the serial loop's msize_max leniency — documented,
         * cf-2-design.md §3.5). resp_need mirrors s->msize and only
         * the reader writes it, so the unlocked read is single-thread
         * consistent. */
        uint32_t gate = p->resp_need;
        if (size < STM_9P_HDR_SIZE || size > gate) {
            pool_lock(p);
            pool_latch_dead_locked(p, STM_EPROTOCOL);
            pool_unlock(p);
            break;
        }

        uint8_t *frame = malloc(size);
        if (!frame) {
            pool_lock(p);
            pool_latch_dead_locked(p, STM_ENOMEM);
            pool_unlock(p);
            break;
        }
        memcpy(frame, hdr, 4u);
        r = stratumd_read_full(fd, frame + 4, size - 4u);
        if (r != 0) {
            free(frame);
            pool_lock(p);
            pool_latch_dead_locked(p, STM_EIO);
            pool_unlock(p);
            break;
        }

        uint8_t  type = frame[4];
        uint16_t tag  = (uint16_t)((uint16_t)frame[5]
                                    | ((uint16_t)frame[6] << 8));

        /* Inline ops — reader-executed, never queued. */
        if (type == STM_9P_TVERSION) {
            int vrc = pool_handle_version(p, frame, size);
            free(frame);
            if (vrc != 0) break;
            continue;
        }
        if (type == STM_9P_TFLUSH) {
            int frc = pool_handle_flush(p, frame, size);
            free(frame);
            if (frc != 0) break;
            continue;
        }

        /* Pre-dispatch Tattach policy gate (TLY-A2-impl-1), exactly as
         * the serial loop applies it — a refusal replies inline and
         * never reaches the dispatcher. */
        {
            uint32_t rlen = 0;
            bool refused = stratumd_check_tattach(frame, size, peer_uid,
                                                    user_policy,
                                                    inline_resp,
                                                    sizeof inline_resp,
                                                    &rlen);
            if (refused) {
                free(frame);
                if (pool_write_inline(p, inline_resp, rlen) != 0) {
                    pool_lock(p);
                    pool_latch_dead_locked(p, STM_EIO);
                    pool_unlock(p);
                    break;
                }
                continue;
            }
        }

        /* RC-4b: sample the socket-pending depth signal BEFORE the
         * pool lock (the fd is stable; no lock needed). A frame
         * arriving after the sample waits one residual service time —
         * the scripture's blessed item-3 semantics. On the dispatch
         * path the syscall cost is noise against the handoff that
         * follows. */
        bool next_pending = pool_socket_pending(p->fd);

        /* Admission. */
        pool_lock(p);

        /* Duplicate in-flight tag = protocol violation, connection-
         * fatal (the wire state is ambiguous; consistent with the
         * serial loop's treatment of an out-of-range size). */
        if (pool_find_live_tag_locked(p, tag)) {
            pool_latch_dead_locked(p, STM_EPROTOCOL);
            pool_unlock(p);
            free(frame);
            break;
        }

        /* RC-4b adaptive dispatch (docs/rc-design.md): with NOTHING in
         * flight AND no further frame buffered, a worker handoff buys
         * zero overlap and costs the wake round-trip — the measured
         * ~9-11% tax on depth-1-dominated windows. Execute inline on
         * the reader instead: n_inflight == 0 means every slot is FREE
         * (QUEUED / EXECUTING / REPLYING / cancelled corpses all
         * count), so every worker is parked on work_cv and the reader
         * is the only thread touching srv — the exact invariant
         * pool_handle_version's quiesce barrier establishes before ITS
         * inline execution; here the barrier condition already holds.
         * The observation is stable across the unlock: the reader is
         * the sole admitter and workers only ever DECREASE n_inflight.
         * The op takes no slot and never enters the registry — no
         * frame can be read while it executes (same thread), so no
         * duplicate tag can form against it, and a Tflush naming its
         * tag arrives only after its reply is on the wire (the
         * not-found arm: immediate Rflush, ordered after the reply by
         * program order + write_mu — CF2-I2 holds). Alloc failure
         * falls through to worker dispatch: inline is an optimization
         * whose failure path is the normal path.
         *
         * BOTH depth terms are load-bearing (audit F1): n_inflight
         * alone SELF-STARVES — inline execution never raises it and
         * the reader cannot read frames while executing inline, so
         * every op would inline forever and the pool would degenerate
         * to the serial loop at every depth. next_pending is the
         * signal that restores dispatch: buffered bytes mean the
         * client has pipelined, so this op overlaps with the burst
         * behind it. */
        if (p->n_inflight == 0 && !next_pending && !p->dead
            && !(g_test_hooks.force_dispatch
                 && g_test_hooks.force_dispatch(g_test_hooks.arg))) {
            uint32_t need = p->resp_need;
            pool_unlock(p);

            if (ilr_cap < need) {
                uint8_t *nr = realloc(ilr, need);
                if (nr) { ilr = nr; ilr_cap = need; }
            }
            if (ilr_cap >= need) {
                if (g_test_hooks.pre_handle)
                    g_test_hooks.pre_handle(g_test_hooks.arg, tag, type);

                uint32_t   rlen = 0;
                stm_status hrc  = stm_9p_server_handle(p->srv, frame, size,
                                                         ilr, ilr_cap,
                                                         &rlen);
                free(frame);
                if (hrc != STM_OK || rlen == 0u) {
                    /* Fatal per the handler contract — identical to the
                     * worker path's latch. */
                    pool_lock(p);
                    pool_latch_dead_locked(
                        p, (hrc == STM_OK) ? STM_EPROTOCOL : hrc);
                    pool_unlock(p);
                    break;
                }
                if (pool_write_inline(p, ilr, rlen) != 0) {
                    pool_lock(p);
                    pool_latch_dead_locked(p, STM_EIO);
                    pool_unlock(p);
                    break;
                }
                continue;
            }
            /* ilr alloc failed — dispatch instead (workers own their
             * buffers; their ENOMEM path latches only on THEIR alloc
             * failure). Re-lock and fall through; the registry is
             * still empty (nothing was read or admitted since the
             * check), so the duplicate gate needs no re-run. */
            pool_lock(p);
            if (p->dead) {          /* unreachable today (only this
                                     * thread latches while idle) —
                                     * defensive symmetry with the
                                     * admission loop below. */
                pool_unlock(p);
                free(frame);
                break;
            }
        }

        pool_slot *sl;
        size_t     budget = pool_byte_budget(gate);
        for (;;) {
            sl = pool_find_free_locked(p);
            if (p->dead) break;
            if (sl && p->queued_bytes + size <= budget) break;
            /* Back-pressure: block the reader (stop consuming the
             * socket) until a slot frees / bytes drain. Sound end to
             * end — the kernel client tolerates a stalled server
             * (the #348/#349 flow-control paths). */
            pthread_cond_wait(&p->slot_cv, &p->mu);
        }
        if (p->dead) {
            pool_unlock(p);
            free(frame);
            break;
        }

        sl->state         = SLOT_QUEUED;
        sl->cancelled     = false;
        sl->flush_pending = false;
        sl->tag           = tag;
        sl->type          = type;
        sl->req           = frame;
        sl->req_len       = size;

        p->ring[(p->ring_head + p->n_queued) % STM_FS_POOL_SLOTS] =
            (uint16_t)(sl - p->slots);
        p->n_queued++;
        p->n_inflight++;
        p->queued_bytes += size;

        pthread_cond_signal(&p->work_cv);
        pool_unlock(p);
    }

    /* Teardown (CF2-I8). Clean EOF drains — queued + executing ops
     * complete and their replies are written (a client may half-close
     * its send side and still read); error paths abandon the queue. */
    pool_lock(p);
    p->draining = true;
    pthread_cond_broadcast(&p->work_cv);
    pthread_cond_broadcast(&p->slot_cv);
    pool_unlock(p);

    for (uint32_t i = 0; i < n_started; i++)
        (void)pthread_join(wh[i].tid, NULL);

    /* Workers exit only on an empty ring; any frame still owned by a
     * slot would be a bookkeeping bug — sweep defensively anyway. */
    for (uint32_t i = 0; i < STM_FS_POOL_SLOTS; i++) {
        free(p->slots[i].req);
        p->slots[i].req = NULL;
    }

    stm_status rc = STM_OK;
    if (p->dead) rc = p->fatal_rc;
    else if (!clean_eof) rc = STM_EIO;

    free(ilr);
    free(wh);
    pthread_mutex_destroy(&p->write_mu);
    pthread_cond_destroy(&p->slot_cv);
    pthread_cond_destroy(&p->work_cv);
    pthread_mutex_destroy(&p->mu);
    free(p);
    return rc;
}
