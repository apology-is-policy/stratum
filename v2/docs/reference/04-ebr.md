# 04 — Epoch-based reclamation (EBR)

## Purpose

Safe lock-free memory reclamation for the Bw-tree delta chains
(`btree_lf`) and any future lock-free data structures that need to
retire pointers without exposing them to reads in flight.

The problem EBR solves: a reader is traversing a delta chain; a
writer CAS-prepends a new delta and wants to free the old chain.
The reader is still walking it. EBR defers the free until every
concurrent reader has moved past the epoch where the retire
happened, so the reader either sees the retired memory entirely
(safe) or never sees it (also safe — reads pinned by a later epoch).

Three-epoch Treiber-ring-of-retires design per ARCHITECTURE §3.6,
modeled in `v2/specs/concurrency.tla`.

## Public API

```c
// Global lifecycle
stm_status stm_ebr_init(void);        // idempotent; safe under concurrent callers
void       stm_ebr_shutdown(void);    // panics if threads still registered

// Per-thread
stm_ebr_thread *stm_ebr_register(void);        // one per real thread
void            stm_ebr_thread_free(stm_ebr_thread *t);

// Epoch participation
void stm_ebr_enter    (stm_ebr_thread *t);    // before reading shared state
void stm_ebr_exit     (stm_ebr_thread *t);    // after
void stm_ebr_heartbeat(stm_ebr_thread *t);    // exit + re-enter; for long ops

// Retirement
typedef void (*stm_ebr_destructor)(void *ptr);
stm_status stm_ebr_retire      (void *ptr, stm_ebr_destructor dtor);
int        stm_ebr_try_advance (void);        // returns # reclaimed, never blocks

// Observability
uint64_t stm_ebr_current_epoch  (void);
uint64_t stm_ebr_pending_retires(void);
uint32_t stm_ebr_thread_count   (void);
```

### Usage pattern

```c
// Thread setup (once):
stm_ebr_thread *me = stm_ebr_register();

// Read-side critical section:
stm_ebr_enter(me);
walk_delta_chain(head);        // may dereference pointers that could be retired
stm_ebr_exit(me);

// Write-side retire-then-replace:
void *new_ = build_new();
atomic_store(&shared_head, new_);
stm_ebr_retire(old, dtor);     // scheduled free; may happen later

// Periodically drive reclamation:
stm_ebr_try_advance();

// Thread teardown:
stm_ebr_thread_free(me);
```

## Implementation

Three epochs (`0, 1, 2`, wrapping modulo 3). A thread "in" the
epoch records the current global epoch at `enter` time; `exit`
clears the record. Retires are stamped with the current global
epoch and pushed onto a per-epoch retire ring via CAS.

`try_advance` does a non-blocking scan:

1. Read all threads' local epochs.
2. If every in-epoch thread is at `current` or `current - 1`, it's
   safe to advance to `current + 1` (two-epochs-ago retires
   guaranteed observed).
3. CAS the global epoch to bump.
4. Drain the `(current - 2) mod 3` retire ring — every retire there
   is safe to destruct.

Invariants:

- **No reader-writer blocking**: `enter` / `exit` are single atomic
  stores. `retire` is a CAS onto a Treiber stack. `try_advance`
  never waits — if a lagging reader blocks advance, it returns 0.
- **Nested enter is NOT supported** — `stm_ebr_enter(t)` twice in a
  row without an intervening `exit` is UB. Callers with nested
  logical operations enter once at the outermost.
- **Heartbeat** is the only sanctioned way to shorten an already-
  active pin, used by long scans (scrub, `btree_lf_scan`) so they
  don't indefinitely stall reclamation.

### Structures

- `struct stm_ebr_thread` — per-thread record: local-epoch atomic,
  next-pointer for the registered-threads singly-linked list. CAS-
  prepended at `register`; unlinked at `thread_free`.
- `struct ebr_retire_ring[3]` — one per epoch. CAS-prepended head
  of retire records.
- Global atomic `current_epoch_u64`.

## Spec cross-reference

`concurrency.tla` models:

- `TypeOK` — every thread's local epoch is in {0,1,2,⊥}; retire
  rings are per-epoch sets of (ptr, dtor) tuples.
- `SafetyNoUseAfterFree` — a thread in epoch E cannot see a pointer
  retired at epoch E-2 or earlier (already reclaimed) or retired at
  E+1 onward (didn't exist yet).
- `ForwardProgress` — if all threads eventually exit or heartbeat,
  advance eventually succeeds.

TLC-verified at `(readers=2, chain≤2, deltas=3, epochs=3)` → 3150
distinct states. The small scope is deliberate: EBR's correctness
is a function of the epoch-advance rule, not of how many pointers
or threads are involved.

## Tests

`tests/test_ebr.c` (~15 tests):

- Single-thread register + enter + exit + thread_free roundtrip.
- Multiple threads (pthread stress, short loops).
- Retire + advance + dtor invocation.
- Advance blocked by a lagging reader; proceeds after its exit.
- Heartbeat drops the pin so advance can proceed.
- `pending_retires` / `current_epoch` observability.
- Nested-enter is UB, so tested indirectly by "enter without exit is
  still reaped at thread_free" (not actually supported; behavior is
  caller-beware).

Used indirectly by every `test_btree_lf` test (the Bw-tree is EBR's
primary consumer).

## Cross-layer integration

| Caller | Pattern |
|---|---|
| `btree_lf` | Every lookup/insert/delete/scan takes an `stm_ebr_thread *`. Writers retire the old chain on consolidation; readers pin via `enter`/`exit`. Scan uses `heartbeat` between leaves so long scans don't stall reclamation. |
| `scrub` (P5-5-α) | **Does NOT use EBR** — scrub doesn't walk lock-free structures. Its only reads are through `stm_alloc_first_allocated_from`, which internally locks an rwlock and flushes messages; no epoch pin needed. |
| Future (send/recv, CAS GC) | Any future lock-free consumer. Register one thread per worker. |

## Status

- [x] Register / thread_free.
- [x] Enter / exit / heartbeat.
- [x] Retire (CAS Treiber-stack prepend).
- [x] Try-advance (non-blocking scan + ring drain).
- [x] Observability accessors.
- [x] Init / shutdown with panic-if-threads-still-registered.

Phase 2 feature-complete. No planned changes.

## Known caveats

- **Stalled readers delay reclamation indefinitely.** A reader that
  enters and never exits (crash, hung, bug) permanently pins an
  epoch. `try_advance` becomes a no-op. Pending retires accumulate.
  Today there is no watchdog; ARCH §3.6.5 notes that a future hook
  could panic on sustained stall.
- **Nested `enter` is UB.** The impl doesn't enforce — it's a caller
  contract. Call sites in `btree_lf` are structured so enter/exit
  is always a flat pair.
- **No priority**: retires drain oldest-epoch-first but within an
  epoch the order is undefined. Destructors must not assume any
  sibling order.
- **Retire allocation failure** returns `STM_ENOMEM`. The retire
  record is ~32 bytes; failure is rare but possible under extreme
  memory pressure. Callers losing a retire leak the pointed-at
  memory (nothing worse — the caller has already swapped the
  pointer out of the shared structure).
