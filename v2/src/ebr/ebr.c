/* SPDX-License-Identifier: ISC */
/*
 * Epoch-based reclamation.
 *
 * Design (from ARCHITECTURE §3.6, refined by v2/specs/concurrency.tla):
 *
 *   global.current_epoch        atomic uint64, starts at 1
 *   global.threads              atomic head of thread_state linked list
 *   global.retired[3]           three Treiber stacks, keyed by (epoch % 3)
 *
 *   thread_state.local_epoch    atomic uint64; INACTIVE (0) when not in an op,
 *                               or the global_epoch value they entered at.
 *   thread_state.alive          atomic bool; false after stm_ebr_thread_free.
 *   thread_state.next           singly-linked next pointer.
 *
 *   retired_object.ptr          pointer to reclaim.
 *   retired_object.destructor   called once when reclamation fires.
 *   retired_object.next         next in the Treiber stack.
 *
 * Invariants (exercised by tests/test_ebr.c; proved at small scope by
 * v2/specs/concurrency.tla):
 *
 *   (A) A thread inside its enter/exit window has local_epoch >= some past
 *       global_epoch. It observes a state no older than its snapshot.
 *
 *   (B) No retired object's destructor fires while any thread's local_epoch
 *       < the retirement epoch — the advance gate ensures this.
 *
 *   (C) Every retired object is freed at most once (Treiber stack is
 *       drained atomically into a thread-local list, then processed).
 *
 * Memory model: we use seq_cst atomics throughout this initial
 * implementation. Phase 9 tuning will relax to acquire/release where
 * safe per ARCHITECTURE §3.6's memory-barrier remarks.
 */
#include <stratum/ebr.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INACTIVE          0u
#define DEAD_SENTINEL     (~(uint64_t)0)

/* 64-byte cache line pad to avoid false sharing between threads. */
#define STM_CACHELINE_PAD 64

struct stm_ebr_thread {
    _Atomic uint64_t  local_epoch;
    _Atomic bool      alive;
    struct stm_ebr_thread *next;
    /* Pad to a full cache line. */
    char _pad[STM_CACHELINE_PAD
              - sizeof(_Atomic uint64_t)
              - sizeof(_Atomic bool)
              - sizeof(struct stm_ebr_thread *)];
};

typedef struct retired_obj {
    void                  *ptr;
    stm_ebr_destructor     destructor;
    uint64_t               retire_epoch;   /* epoch at which this was retired */
    struct retired_obj    *next;
} retired_obj;

struct ebr_global {
    _Atomic uint64_t               current_epoch;
    _Atomic(struct stm_ebr_thread *) threads;        /* lock-free list head */
    _Atomic(retired_obj *)         retired[3];       /* Treiber stacks */
    _Atomic uint32_t               thread_count;
    _Atomic uint64_t               pending_retires;  /* best-effort counter */
    _Atomic bool                   initialized;
};

static struct ebr_global g;
static pthread_once_t    g_init_once = PTHREAD_ONCE_INIT;

/* ========================================================================= */
/* Initialization.                                                            */
/* ========================================================================= */

static void init_once_impl(void)
{
    atomic_store(&g.current_epoch, 1);
    atomic_store(&g.threads, NULL);
    for (int i = 0; i < 3; i++) atomic_store(&g.retired[i], NULL);
    atomic_store(&g.thread_count, 0);
    atomic_store(&g.pending_retires, 0);
    atomic_store(&g.initialized, true);
}

stm_status stm_ebr_init(void)
{
    pthread_once(&g_init_once, init_once_impl);
    return STM_OK;
}

/* ========================================================================= */
/* Thread registration.                                                       */
/* ========================================================================= */

stm_ebr_thread *stm_ebr_register(void)
{
    if (!atomic_load(&g.initialized)) {
        stm_status s = stm_ebr_init();
        if (s != STM_OK) return NULL;
    }

    /* C11 aligned_alloc requires size to be a multiple of alignment; macOS
     * libc enforces this strictly. Use posix_memalign which has no such
     * constraint. */
    void *raw = NULL;
    if (posix_memalign(&raw, STM_CACHELINE_PAD, sizeof(stm_ebr_thread)) != 0)
        return NULL;
    stm_ebr_thread *t = raw;
    memset(t, 0, sizeof *t);
    atomic_init(&t->local_epoch, INACTIVE);
    atomic_init(&t->alive, true);

    /* CAS prepend onto g.threads. */
    stm_ebr_thread *old_head = atomic_load(&g.threads);
    do {
        t->next = old_head;
    } while (!atomic_compare_exchange_weak(&g.threads, &old_head, t));

    atomic_fetch_add(&g.thread_count, 1);
    return t;
}

void stm_ebr_thread_free(stm_ebr_thread *t)
{
    if (!t) return;
    /* Must not be in an epoch when freeing. Assertion via DEAD sentinel:
     * after this, enter/exit on this handle are undefined. */
    atomic_store(&t->alive, false);
    atomic_store(&t->local_epoch, DEAD_SENTINEL);
    /* Memory is leaked until shutdown. Acceptable: thread counts are
     * bounded in our use case. Aggressive unlink would race with a
     * concurrent try_advance walking the list. */
}

/* ========================================================================= */
/* Enter / exit.                                                              */
/* ========================================================================= */

void stm_ebr_enter(stm_ebr_thread *t)
{
    uint64_t e = atomic_load(&g.current_epoch);
    /* Seq-cst store ensures a later retirer's load sees our local_epoch. */
    atomic_store(&t->local_epoch, e);
}

void stm_ebr_exit(stm_ebr_thread *t)
{
    atomic_store(&t->local_epoch, INACTIVE);
}

void stm_ebr_heartbeat(stm_ebr_thread *t)
{
    stm_ebr_exit(t);
    stm_ebr_enter(t);
}

/* ========================================================================= */
/* Retire + advance.                                                          */
/* ========================================================================= */

stm_status stm_ebr_retire(void *ptr, stm_ebr_destructor destructor)
{
    if (!ptr || !destructor) return STM_EINVAL;

    retired_obj *r = malloc(sizeof *r);
    if (!r) return STM_ENOMEM;
    r->ptr          = ptr;
    r->destructor   = destructor;

    uint64_t e = atomic_load(&g.current_epoch);
    r->retire_epoch = e;
    int bucket = (int)(e % 3);

    /* CAS prepend. */
    retired_obj *old_head = atomic_load(&g.retired[bucket]);
    do {
        r->next = old_head;
    } while (!atomic_compare_exchange_weak(&g.retired[bucket], &old_head, r));

    atomic_fetch_add(&g.pending_retires, 1);
    return STM_OK;
}

/*
 * Examine all thread entries; if every alive thread's local_epoch is
 * either INACTIVE or ≥ global_epoch, it's safe to advance.
 *
 * Uses a single walk (no double-sampling). A thread entering during the
 * walk may publish local_epoch == current_epoch after we've read their
 * slot; that's fine because the advance is still safe (they would see the
 * current epoch's state, never an older retirement).
 */
static bool can_advance(uint64_t current)
{
    for (stm_ebr_thread *t = atomic_load(&g.threads); t; t = t->next) {
        if (!atomic_load(&t->alive)) continue;
        uint64_t le = atomic_load(&t->local_epoch);
        if (le == INACTIVE || le == DEAD_SENTINEL) continue;
        if (le < current) return false;
    }
    return true;
}

/*
 * Atomically snatch the retired list at bucket `b`. After this, the bucket
 * is empty; subsequent retires prepend to the cleared head (possibly
 * targeting the same bucket if another thread advances the epoch quickly).
 */
static retired_obj *steal_bucket(int b)
{
    retired_obj *head = atomic_exchange(&g.retired[b], NULL);
    return head;
}

/*
 * Drain stolen list `head`, freeing only records whose retire_epoch is
 * safe (< safe_before). Records not yet safe — stragglers from a racing
 * retire after the epoch advanced — are pushed back onto the bucket's
 * stack for a future drain.
 */
static int drain_list_filtered(retired_obj *head, int bucket, uint64_t safe_before)
{
    int freed = 0;
    while (head) {
        retired_obj *next = head->next;
        if (head->retire_epoch < safe_before) {
            head->destructor(head->ptr);
            free(head);
            freed++;
        } else {
            /* Push back onto the bucket. Rare — only under heavy races
             * where a retire observed the pre-advance epoch and landed in
             * the now-being-drained bucket. */
            retired_obj *h = atomic_load(&g.retired[bucket]);
            do {
                head->next = h;
            } while (!atomic_compare_exchange_weak(&g.retired[bucket], &h, head));
        }
        head = next;
    }
    return freed;
}

/* Unfiltered drain for shutdown. */
static int drain_list_all(retired_obj *head)
{
    int n = 0;
    while (head) {
        retired_obj *next = head->next;
        head->destructor(head->ptr);
        free(head);
        head = next;
        n++;
    }
    return n;
}

int stm_ebr_try_advance(void)
{
    uint64_t e = atomic_load(&g.current_epoch);

    if (!can_advance(e)) return 0;

    /* CAS the epoch forward. Another thread might race; if it wins, we
     * bail — it will do the reclamation for this epoch. */
    uint64_t expected = e;
    if (!atomic_compare_exchange_strong(&g.current_epoch, &expected, e + 1)) {
        return 0;
    }

    /* We advanced from e to e+1. Reclaim bucket (e - 2) mod 3 — two
     * epochs behind. When e < 2 there's nothing retired yet at that depth.
     * We use unsigned modular arithmetic: (e - 2) mod 3 for e >= 2. */
    if (e < 2) return 0;
    int bucket = (int)((e - 2) % 3);

    /* Only free records whose retire_epoch < e - 1 (i.e. records retired at
     * epoch e-2 or earlier). After the advance the current_epoch is e+1,
     * so objects retired at e-2 have satisfied the "2 epochs behind" rule.
     * A racy retire from the pre-advance window lands in this same bucket
     * with retire_epoch == e and gets put back. */
    uint64_t safe_before = e - 1;
    retired_obj *to_free = steal_bucket(bucket);
    int freed = drain_list_filtered(to_free, bucket, safe_before);

    if (freed > 0) {
        /* Best-effort: don't go negative if the counter is out of sync. */
        uint64_t current = atomic_load(&g.pending_retires);
        while (current > 0 && freed > 0) {
            uint64_t sub = ((uint64_t)freed > current) ? current : (uint64_t)freed;
            if (atomic_compare_exchange_weak(&g.pending_retires,
                                             &current, current - sub))
                break;
        }
    }
    return freed;
}

/* ========================================================================= */
/* Observability.                                                             */
/* ========================================================================= */

uint64_t stm_ebr_current_epoch(void)
{
    return atomic_load(&g.current_epoch);
}

uint64_t stm_ebr_pending_retires(void)
{
    return atomic_load(&g.pending_retires);
}

uint32_t stm_ebr_thread_count(void)
{
    return atomic_load(&g.thread_count);
}

/* ========================================================================= */
/* Shutdown.                                                                  */
/* ========================================================================= */

void stm_ebr_shutdown(void)
{
    /* Drain all buckets unconditionally (caller promises no threads are
     * using EBR). */
    for (int b = 0; b < 3; b++) {
        retired_obj *head = steal_bucket(b);
        (void)drain_list_all(head);
    }

    /* Free dead thread entries. We keep alive ones (should not happen if
     * caller observed the contract). */
    stm_ebr_thread *t = atomic_load(&g.threads);
    atomic_store(&g.threads, NULL);
    while (t) {
        stm_ebr_thread *next = t->next;
        free(t);
        t = next;
    }
    atomic_store(&g.thread_count, 0);
    atomic_store(&g.pending_retires, 0);
    atomic_store(&g.current_epoch, 1);
    atomic_store(&g.initialized, false);
    /* Reset the pthread_once barrier so the next init actually runs. */
    static const pthread_once_t fresh_once = PTHREAD_ONCE_INIT;
    g_init_once = fresh_once;
}
