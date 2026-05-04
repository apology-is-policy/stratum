---------------------------- MODULE inode ----------------------------
\* Stratum v2 Phase 8 — inode allocation + generation counter.
\*
\*   ARCHITECTURE §11.3 (Inode format) — `si_gen` semantics.
\*   ARCHITECTURE §11.3.2 (Generation number).
\*   ROADMAP    §11.1 (Phase 8 deliverable: inode layer).
\*
\* Pin: the (ino, gen) tuple uniquely identifies an inode FOR ALL TIME
\* — across delete-and-reuse cycles, across mounts, across years. This
\* is the foundation for stale-fid detection in 9P (ARCH §11.3.2),
\* per-file derived keys (§7.3.3), and NFS file handles (§11.3.2).
\*
\* The single most consequential invariant: an inode whose number gets
\* reused MUST have gen strictly greater than any prior allocation at
\* that number. A buggy implementation that reuses without bumping
\* gen exposes the entire system to confusing-deputy attacks
\* (a 9P client holding a fid for ino X gen 5 is silently rerouted
\* to a freshly-created file at ino X gen 5, with potentially
\* different access rights). The spec models the bug via
\* BuggyReuseNoGenBump and demonstrates the violation.
\*
\* Scope. The spec models the inode allocator's STATE MACHINE only:
\*
\*   - State of each ino: NEVER_USED, ALLOCATED, FREED.
\*   - Generation counter per ino (Nat).
\*   - next_ino high-water mark.
\*
\* Out of scope (deferred to later P8-POSIX-* specs):
\*   - nlink semantics (P8-POSIX-3).
\*   - Tagged data union state (extent / inline / symlink / device,
\*     P8-POSIX-5 covers the inline-to-extent transition).
\*   - Hard link sibling ino (P8-POSIX-3).
\*   - Per-dataset inode space partitioning (assumed; the spec is
\*     parametric over a single dataset's ino space — multi-dataset
\*     reduces to per-dataset by isolation).
\*   - On-disk persistence semantics (the inode tree is a
\*     btree_store of (ino → 256B value); structural correctness
\*     follows from sync.tla + btree write paths).

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Inos,                          \* finite set of possible ino numbers
                                   \*   (e.g., {1, 2, 3, 4})
    MaxGen,                        \* bound on generation counter
                                   \*   (TLC tractability; real impl
                                   \*    uses uint64_t)
    MaxNlink,                      \* bound on per-ino nlink counter
                                   \*   (P8-POSIX-3; real impl is u32).
    BuggyReuseNoGenBump,           \* TRUE → AllocReused does not bump
                                   \*   gen. Demonstrates the canonical
                                   \*   stale-fid-attack failure mode.
    BuggyDoubleAllocate,           \* TRUE → AllocFresh also picks
                                   \*   already-ALLOCATED inos.
                                   \*   Demonstrates allocator
                                   \*   double-issue.
    BuggyUnlinkLeavesZeroNlink,    \* TRUE → Unlink decrements nlink
                                   \*   to 0 but leaves ALLOCATED state
                                   \*   (no cascade-free). Demonstrates
                                   \*   the "ALLOCATED+nlink=0" orphan
                                   \*   that R71 P1-1 caught at the
                                   \*   writer-side guard.
    EnableInlineDataModel,         \* TRUE → enable data_kind /
                                   \*   data_len / ever_extent shadow
                                   \*   tracking + the 5 inline-
                                   \*   specific actions in Next
                                   \*   (P8-POSIX-5). FALSE → existing
                                   \*   actions UNCHANGED on these
                                   \*   vars, so existing configs (e.g.,
                                   \*   inode.cfg's 9.87M-state run)
                                   \*   don't explode their state space.
    MaxFileLen,                    \* bound on file logical size
                                   \*   (TLC tractability; real impl
                                   \*    uses uint64_t).
    MaxInline,                     \* inline-storage cap (≤ MaxFileLen).
                                   \*   Real impl: STM_INODE_INLINE_MAX
                                   \*   = 100 bytes (ARCH §11.3.3).
    BuggyTruncateReinlines,        \* TRUE → TruncateExtent shrinking
                                   \*   to ≤ MaxInline transitions
                                   \*   data_kind back to "inline" —
                                   \*   violates ARCH §11.3.3's one-
                                   \*   way INLINE → EXTENT semantics
                                   \*   ("once extent-backed, stays
                                   \*    extent-backed").
    BuggyInlineWriteSpills,        \* TRUE → WriteInline allows
                                   \*   data_len > MaxInline without
                                   \*   transitioning. Demonstrates
                                   \*   the "data spilled past inline
                                   \*   cap but kind still claims
                                   \*   INLINE" corruption shape.
    EnableOrphanModel,             \* TRUE → enable orphan-state shadow
                                   \*   tracking + AllocAnon /
                                   \*   Materialize / FreeAnon actions
                                   \*   (P8-POSIX-7a-anon, O_TMPFILE).
                                   \*   FALSE → existing actions
                                   \*   UNCHANGED on ever_linked, so
                                   \*   existing inode.cfg's 9.87M-
                                   \*   state run is unaffected (Init
                                   \*   sets ever_linked = TRUE for
                                   \*   every ino, so the reformulated
                                   \*   LinkedAllocatedHasPositiveNlink
                                   \*   reduces to its pre-7a form).
    BuggyAllocAnonClaimsLinked     \* TRUE → AllocAnon sets
                                   \*   ever_linked = TRUE while
                                   \*   leaving nlink = 0. Demonstrates
                                   \*   the "linked file with nlink=0"
                                   \*   shape that
                                   \*   LinkedAllocatedHasPositiveNlink
                                   \*   catches. Pinned at the spec
                                   \*   level so a buggy O_TMPFILE
                                   \*   impl that conflates linked +
                                   \*   orphan states is provably
                                   \*   detected.

ASSUME /\ Inos # {}
       /\ MaxGen \in Nat /\ MaxGen >= 1
       /\ MaxNlink \in Nat /\ MaxNlink >= 1
       /\ BuggyReuseNoGenBump \in BOOLEAN
       /\ BuggyDoubleAllocate \in BOOLEAN
       /\ BuggyUnlinkLeavesZeroNlink \in BOOLEAN
       /\ EnableInlineDataModel \in BOOLEAN
       /\ MaxFileLen \in Nat
       /\ MaxInline \in Nat /\ MaxInline <= MaxFileLen
       /\ BuggyTruncateReinlines \in BOOLEAN
       /\ BuggyInlineWriteSpills \in BOOLEAN
       /\ EnableOrphanModel \in BOOLEAN
       /\ BuggyAllocAnonClaimsLinked \in BOOLEAN

\* Inode states.
NEVER_USED == "never_used"
ALLOCATED  == "allocated"
FREED      == "freed"

\* Data-kind tags (P8-POSIX-5). On-disk equivalents live in
\* `include/stratum/inode.h` as STM_DATA_INLINE / STM_DATA_EXTENT;
\* "none" is the spec sentinel for NEVER_USED / FREED inos and has
\* no on-disk encoding (the inode record itself doesn't exist for
\* NEVER_USED, and is FREED-flagged for FREED).
KIND_NONE   == "none"
KIND_INLINE == "inline"
KIND_EXTENT == "extent"

\* --------------------------------------------------------------------------
\* State.
\*
\*   state : Inos -> {NEVER_USED, ALLOCATED, FREED}
\*       Per-ino lifecycle state.
\*
\*   gen : Inos -> Nat
\*       Generation counter. Starts at 0 for NEVER_USED. Set to 0 at
\*       first AllocFresh. Incremented on AllocReused (healthy
\*       contract) or NOT incremented (BuggyReuseNoGenBump).
\*
\*   history : Inos -> Set of (gen, "alloc-event-id") tuples
\*       Audit trail of every allocation event for this ino. The
\*       headline invariant TupleUniqueAllTime examines history to
\*       assert no (ino, gen) tuple ever appears twice across the
\*       full execution. Models a "the world remembers every fid
\*       ever issued" property.
\*
\*   alloc_event_counter : Nat
\*       Monotonic event counter; each Alloc* action stamps the
\*       resulting (ino, gen) into history with a fresh event id.
\* --------------------------------------------------------------------------

VARIABLES
    state,
    gen,
    nlink,                         \* per-ino hard-link counter
                                   \*   (P8-POSIX-3 extension).
    history,
    alloc_event_counter,
    data_kind,                     \* per-ino data layout tag
                                   \*   (P8-POSIX-5): KIND_NONE for
                                   \*   non-ALLOCATED inos, KIND_INLINE
                                   \*   for inline-stored data,
                                   \*   KIND_EXTENT for extent-tree-
                                   \*   stored data.
    data_len,                      \* per-ino logical size
                                   \*   (P8-POSIX-5). For KIND_INLINE
                                   \*   inos, the bound `data_len <=
                                   \*   MaxInline` is the load-bearing
                                   \*   invariant. For KIND_EXTENT the
                                   \*   spec doesn't track length —
                                   \*   the extent layer manages that.
    ever_extent,                   \* per-ino BOOLEAN (P8-POSIX-5):
                                   \*   set TRUE on first
                                   \*   TransitionToExtent; reset on
                                   \*   AllocReused / cascade-free.
                                   \*   Pins the one-way "once EXTENT,
                                   \*   stays EXTENT until freed"
                                   \*   property — a buggy
                                   \*   TruncateExtent that reverts
                                   \*   to KIND_INLINE while
                                   \*   ever_extent[i] = TRUE fires
                                   \*   the OneWayInlineToExtent
                                   \*   invariant.
    ever_linked                    \* per-ino BOOLEAN (P8-POSIX-7a-anon):
                                   \*   tracks whether THIS allocation
                                   \*   has ever been linked to a
                                   \*   dirent (or carries a non-zero
                                   \*   nlink). AllocFresh / AllocReused
                                   \*   set TRUE; AllocAnon sets FALSE
                                   \*   (orphan state); Materialize
                                   \*   flips FALSE → TRUE.
                                   \*
                                   \*   Init: TRUE for every ino — when
                                   \*   EnableOrphanModel = FALSE the
                                   \*   pre-existing actions don't
                                   \*   touch ever_linked, so all
                                   \*   ALLOCATED inos have
                                   \*   ever_linked = TRUE and the
                                   \*   reformulated invariant reduces
                                   \*   to its pre-7a form. Healthy
                                   \*   behavior under EnableOrphanModel
                                   \*   = TRUE: AllocFresh / AllocReused
                                   \*   explicitly set TRUE; AllocAnon
                                   \*   sets FALSE; Materialize sets
                                   \*   TRUE. Cascade-free + FreeAnon
                                   \*   leave ever_linked unchanged
                                   \*   (FREED inos don't use it; reset
                                   \*   happens at the next allocation).

vars == <<state, gen, nlink, history, alloc_event_counter,
          data_kind, data_len, ever_extent, ever_linked>>

\* --------------------------------------------------------------------------
\* Initial state — all inos NEVER_USED, all gen=0, empty history.
\* --------------------------------------------------------------------------

Init ==
    /\ state               = [i \in Inos |-> NEVER_USED]
    /\ gen                 = [i \in Inos |-> 0]
    /\ nlink               = [i \in Inos |-> 0]
    /\ history             = [i \in Inos |-> {}]
    /\ alloc_event_counter = 0
    /\ data_kind           = [i \in Inos |-> KIND_NONE]
    /\ data_len            = [i \in Inos |-> 0]
    /\ ever_extent         = [i \in Inos |-> FALSE]
    /\ ever_linked         = [i \in Inos |-> TRUE]

\* --------------------------------------------------------------------------
\* Helpers.
\* --------------------------------------------------------------------------

\* The set of ALLOCATED inos.
AllocatedSet == {i \in Inos : state[i] = ALLOCATED}

\* The set of FREED inos.
FreedSet == {i \in Inos : state[i] = FREED}

\* The set of NEVER_USED inos.
NeverUsedSet == {i \in Inos : state[i] = NEVER_USED}

\* --------------------------------------------------------------------------
\* Actions.
\* --------------------------------------------------------------------------

\* AllocFresh: pick a NEVER_USED ino, mark ALLOCATED with gen=0.
\* Healthy: only NEVER_USED inos eligible. nlink starts at 1 (the
\* dirent that the alloc action models is being created in lockstep).
\* BuggyDoubleAllocate: also accepts ALLOCATED inos (silent
\* re-issue of an in-use ino number).
\*
\* P8-POSIX-5 (when EnableInlineDataModel=TRUE): a fresh inode starts
\* in KIND_INLINE with data_len=0; ever_extent=FALSE so the one-way
\* invariant restarts at every fresh alloc.
AllocFresh(i) ==
    /\ \/ state[i] = NEVER_USED
       \/ /\ BuggyDoubleAllocate
          /\ state[i] = ALLOCATED
    /\ gen[i] + 0 <= MaxGen
    /\ state'               = [state EXCEPT ![i] = ALLOCATED]
    /\ gen'                 = [gen   EXCEPT ![i] = 0]
    /\ nlink'               = [nlink EXCEPT ![i] = 1]
    /\ alloc_event_counter' = alloc_event_counter + 1
    /\ history'             = [history EXCEPT
                                  ![i] = history[i] \cup
                                          {<<0, alloc_event_counter + 1>>}]
    \* P8-POSIX-7a-anon: AllocFresh's healthy contract is "create
    \* an inode that's already linked to a dirent" — set ever_linked
    \* := TRUE. AllocReused does the same; only AllocAnon leaves
    \* ever_linked = FALSE.
    /\ ever_linked' = [ever_linked EXCEPT ![i] = TRUE]
    /\ \/ /\ EnableInlineDataModel
          /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_INLINE]
          /\ data_len'    = [data_len EXCEPT ![i] = 0]
          /\ ever_extent' = [ever_extent EXCEPT ![i] = FALSE]
       \/ /\ ~EnableInlineDataModel
          /\ UNCHANGED <<data_kind, data_len, ever_extent>>

\* AllocReused: pick a FREED ino, mark ALLOCATED. Healthy: bump gen.
\* BuggyReuseNoGenBump: keep prior gen — the canonical (ino, gen)
\* aliasing bug.
\*
\* P8-POSIX-5: same as AllocFresh — a re-allocated inode gets a fresh
\* data lifecycle (KIND_INLINE, data_len=0, ever_extent=FALSE). The
\* one-way "once EXTENT, stays EXTENT" property only applies WITHIN
\* a single allocation; reuse legitimately resets it.
AllocReused(i) ==
    /\ state[i] = FREED
    /\ LET new_gen ==
            IF BuggyReuseNoGenBump THEN gen[i]
            ELSE gen[i] + 1
       IN
        /\ new_gen <= MaxGen
        /\ state'               = [state EXCEPT ![i] = ALLOCATED]
        /\ gen'                 = [gen   EXCEPT ![i] = new_gen]
        /\ nlink'               = [nlink EXCEPT ![i] = 1]
        /\ alloc_event_counter' = alloc_event_counter + 1
        /\ history'             = [history EXCEPT
                                      ![i] = history[i] \cup
                                              {<<new_gen,
                                                 alloc_event_counter + 1>>}]
        \* P8-POSIX-7a-anon: AllocReused's healthy contract matches
        \* AllocFresh — the new allocation IS linked. ever_linked must
        \* be reset to TRUE here to clear any orphan-state remnant
        \* from a prior AllocAnon → FreeAnon cycle on this slot.
        /\ ever_linked' = [ever_linked EXCEPT ![i] = TRUE]
        /\ \/ /\ EnableInlineDataModel
              /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_INLINE]
              /\ data_len'    = [data_len EXCEPT ![i] = 0]
              /\ ever_extent' = [ever_extent EXCEPT ![i] = FALSE]
           \/ /\ ~EnableInlineDataModel
              /\ UNCHANGED <<data_kind, data_len, ever_extent>>

\* Link: ALLOCATED ino with nlink in [1, MaxNlink-1] gets nlink + 1.
\* Models stm_fs_link adding a new dirent that references this ino.
\* The "resurrect FREED via Link" bug is OUT OF SPEC SCOPE for this
\* chunk — catching it cleanly requires a per-ino "last-free event"
\* shadow var to detect "ALLOCATED state set without a fresh alloc-
\* event" patterns. The C impl's Link API simply rejects FREED state
\* with STM_ENOENT (mirrors stm_inode_set's existing FREED guard);
\* the writer-side reject is symmetric with the decoder-side
\* invariant LinkedAllocatedHasPositiveNlink + FreedHasZeroNlink
\* via the cascade-free that Unlink performs.
Link(i) ==
    /\ state[i] = ALLOCATED
    /\ nlink[i] >= 1
    /\ nlink[i] < MaxNlink
    /\ nlink' = [nlink EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<state, gen, history, alloc_event_counter,
                    data_kind, data_len, ever_extent, ever_linked>>

\* Unlink: ALLOCATED ino with nlink >= 1 gets nlink - 1. If healthy
\* and nlink reaches 0, atomically transitions to FREED (cascade-
\* free). BuggyUnlinkLeavesZeroNlink: leaves ALLOCATED state when
\* nlink reaches 0 — produces the (ALLOCATED, nlink=0) orphan that
\* R71 P1-1 caught at the writer-side guard.
Unlink(i) ==
    /\ state[i] = ALLOCATED
    /\ nlink[i] >= 1
    /\ LET new_nlink == nlink[i] - 1
           cascade_free == new_nlink = 0 /\ ~BuggyUnlinkLeavesZeroNlink
       IN
        /\ nlink' = [nlink EXCEPT ![i] = new_nlink]
        /\ state' = IF cascade_free
                    THEN [state EXCEPT ![i] = FREED]
                    ELSE state
        \* P8-POSIX-5: cascade-free clears data_kind / data_len /
        \* ever_extent so a subsequent AllocReused starts a fresh
        \* data lifecycle. Non-cascade Unlinks (nlink decremented but
        \* still > 0) leave data state alone. With
        \* EnableInlineDataModel=FALSE, all data state is UNCHANGED
        \* regardless of cascade.
        /\ \/ /\ EnableInlineDataModel
              /\ \/ /\ cascade_free
                    /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_NONE]
                    /\ data_len'    = [data_len EXCEPT ![i] = 0]
                    /\ ever_extent' = [ever_extent EXCEPT ![i] = FALSE]
                 \/ /\ ~cascade_free
                    /\ UNCHANGED <<data_kind, data_len, ever_extent>>
           \/ /\ ~EnableInlineDataModel
              /\ UNCHANGED <<data_kind, data_len, ever_extent>>
        \* P8-POSIX-7a-anon: Unlink preserves ever_linked. The inode's
        \* "ever-linked" status doesn't reset until a fresh AllocFresh /
        \* AllocReused / AllocAnon. Cascade-free leaves the slot in
        \* FREED state with ever_linked still TRUE, but FREED inos
        \* don't enter the LinkedAllocatedHasPositiveNlink antecedent.
        /\ UNCHANGED <<gen, history, alloc_event_counter, ever_linked>>

\* --------------------------------------------------------------------------
\* P8-POSIX-5 — inline data layout actions.
\*
\* These five actions model the inline ↔ extent-tree transition per
\* ARCH §11.3.3:
\*
\*   - WriteInline:        INLINE → INLINE (data_len grows or shrinks
\*                         within MaxInline; healthy precond bounds
\*                         data_len ≤ MaxInline; BuggyInlineWriteSpills
\*                         drops the bound).
\*   - TransitionToExtent: INLINE → EXTENT (one-way; sets ever_extent
\*                         to TRUE so the OneWayInlineToExtent
\*                         invariant catches any future revert).
\*   - WriteExtent:        EXTENT → EXTENT (no-op at spec level —
\*                         the extent layer manages length and
\*                         layout; the spec only tracks kind).
\*   - TruncateInline:     INLINE → INLINE (data_len shrinks).
\*   - TruncateExtent:     EXTENT → EXTENT (healthy: kind preserved
\*                         even when new_len ≤ MaxInline;
\*                         BuggyTruncateReinlines reverts to
\*                         KIND_INLINE — fires
\*                         OneWayInlineToExtent).
\*
\* All five actions are gated by EnableInlineDataModel=TRUE in Next
\* — when the flag is FALSE, none fire and the spec collapses to
\* the P8-POSIX-1/3 alloc/link/unlink semantics.
\* --------------------------------------------------------------------------

\* WriteInline: write `new_len` bytes to an INLINE-state inode.
\*
\* Precondition: ALLOCATED + KIND_INLINE.
\*
\* Healthy: new_len ≤ MaxInline.
\* BuggyInlineWriteSpills: new_len > MaxInline allowed — fires
\* InlineLenBounded.
WriteInline(i, new_len) ==
    /\ state[i] = ALLOCATED
    /\ data_kind[i] = KIND_INLINE
    /\ new_len \in 0..MaxFileLen
    /\ \/ /\ ~BuggyInlineWriteSpills
          /\ new_len <= MaxInline
       \/ BuggyInlineWriteSpills
    /\ data_len' = [data_len EXCEPT ![i] = new_len]
    /\ UNCHANGED <<state, gen, nlink, history, alloc_event_counter,
                    data_kind, ever_extent, ever_linked>>

\* TransitionToExtent: a write that grows an INLINE inode past
\* MaxInline triggers the cutover. ARCH §11.3.3 step:
\*   1. Allocate extent storage.
\*   2. Write combined (existing inline + new) data to the extent.
\*   3. Update inode: si_data_kind = STM_DATA_EXTENT,
\*      si_extent_tree_root = <new extent tree root>.
\*
\* The spec abstracts the extent allocation + write — the only
\* state change relevant here is data_kind: INLINE → EXTENT, and
\* setting ever_extent[i] := TRUE. data_len is reset to 0 because
\* the extent layer now manages length.
TransitionToExtent(i) ==
    /\ state[i] = ALLOCATED
    /\ data_kind[i] = KIND_INLINE
    /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_EXTENT]
    /\ data_len'    = [data_len EXCEPT ![i] = 0]
    /\ ever_extent' = [ever_extent EXCEPT ![i] = TRUE]
    /\ UNCHANGED <<state, gen, nlink, history, alloc_event_counter,
                    ever_linked>>

\* WriteExtent: a write to an already-EXTENT inode is a no-op at
\* the spec level (the extent layer's invariants are pinned by
\* extent.tla; this spec only models the kind transition).
WriteExtent(i) ==
    /\ state[i] = ALLOCATED
    /\ data_kind[i] = KIND_EXTENT
    /\ UNCHANGED vars

\* TruncateInline: truncate an INLINE inode to `new_len`. Shrinks
\* data_len; kind stays INLINE. (Growing truncate would land in the
\* WriteInline / TransitionToExtent path depending on size.)
TruncateInline(i, new_len) ==
    /\ state[i] = ALLOCATED
    /\ data_kind[i] = KIND_INLINE
    /\ new_len \in 0..MaxFileLen
    /\ new_len <= data_len[i]   \* shrinking
    /\ data_len' = [data_len EXCEPT ![i] = new_len]
    /\ UNCHANGED <<state, gen, nlink, history, alloc_event_counter,
                    data_kind, ever_extent, ever_linked>>

\* TruncateExtent: truncate an EXTENT inode to `new_len`. Per
\* ARCH §11.3.3: "Once extent-backed, stays extent-backed" — even
\* when truncating to a size that would have fit inline.
\*
\* Healthy: kind STAYS EXTENT regardless of new_len.
\* BuggyTruncateReinlines: when new_len ≤ MaxInline, kind reverts
\*   to INLINE. Fires OneWayInlineToExtent (ever_extent[i] is
\*   still TRUE from the prior TransitionToExtent).
TruncateExtent(i, new_len) ==
    /\ state[i] = ALLOCATED
    /\ data_kind[i] = KIND_EXTENT
    /\ new_len \in 0..MaxFileLen
    /\ \/ /\ ~BuggyTruncateReinlines
          /\ UNCHANGED vars   \* kind preserved; spec doesn't track extent length
       \/ /\ BuggyTruncateReinlines
          /\ new_len <= MaxInline
          /\ data_kind' = [data_kind EXCEPT ![i] = KIND_INLINE]
          /\ data_len'  = [data_len EXCEPT ![i] = new_len]
          /\ UNCHANGED <<state, gen, nlink, history, alloc_event_counter,
                          ever_extent, ever_linked>>   \* ever_extent stays TRUE (the bug)

\* --------------------------------------------------------------------------
\* P8-POSIX-7a-anon — orphan inode + Materialize.
\*
\* Linux O_TMPFILE creates a regular-file inode with no dirent
\* (nlink=0, "anonymous"). The inode lives until either materialized
\* via linkat(2) (orphan → linked, nlink 0→1, ever_linked F→T) or
\* explicitly freed via close-with-no-link (orphan → freed). The
\* spec models all three transitions as separate actions:
\*
\*   - AllocAnon:    NEVER_USED / FREED → ALLOCATED (nlink=0,
\*                   ever_linked=FALSE). Matches stm_fs_create_anon.
\*   - Materialize:  ALLOCATED + nlink=0 + ~ever_linked
\*                   → ALLOCATED + nlink=1 + ever_linked=TRUE.
\*                   Matches stm_fs_linkat_anon.
\*   - FreeAnon:     ALLOCATED + nlink=0 + ~ever_linked → FREED.
\*                   Matches stm_fs_unlink_anon.
\*
\* The orphan state is the ONLY way an ALLOCATED inode can have
\* nlink=0 (post-AllocAnon, pre-Materialize). Once materialized,
\* the inode behaves identically to one created via AllocFresh +
\* never goes back to orphan. The relaxed
\* LinkedAllocatedHasPositiveNlink invariant pins this:
\*   ALLOCATED + ever_linked → nlink ≥ 1
\* and the new OrphanHasZeroNlink invariant pins the dual:
\*   ALLOCATED + ~ever_linked → nlink = 0
\*
\* All three actions gated on EnableOrphanModel; FALSE collapses
\* the spec to its pre-7a-anon shape.
\* --------------------------------------------------------------------------

\* AllocAnon: pick a NEVER_USED or FREED ino, mark ALLOCATED with
\* nlink=0 + ever_linked=FALSE. Models stm_fs_create_anon
\* (O_TMPFILE-equivalent).
\*
\* Healthy: nlink := 0, ever_linked := FALSE.
\* BuggyAllocAnonClaimsLinked: ever_linked := TRUE (orphan misclaimed
\* as linked; combined with nlink=0 fires
\* LinkedAllocatedHasPositiveNlink).
AllocAnon(i) ==
    /\ EnableOrphanModel
    /\ \/ state[i] = NEVER_USED
       \/ state[i] = FREED
    /\ LET new_gen ==
            IF state[i] = NEVER_USED THEN 0
            ELSE gen[i] + 1
       IN
        /\ new_gen <= MaxGen
        /\ state'               = [state EXCEPT ![i] = ALLOCATED]
        /\ gen'                 = [gen   EXCEPT ![i] = new_gen]
        /\ nlink'               = [nlink EXCEPT ![i] = 0]
        /\ alloc_event_counter' = alloc_event_counter + 1
        /\ history'             = [history EXCEPT
                                      ![i] = history[i] \cup
                                              {<<new_gen,
                                                 alloc_event_counter + 1>>}]
        /\ ever_linked' = IF BuggyAllocAnonClaimsLinked
                          THEN [ever_linked EXCEPT ![i] = TRUE]
                          ELSE [ever_linked EXCEPT ![i] = FALSE]
        /\ \/ /\ EnableInlineDataModel
              /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_INLINE]
              /\ data_len'    = [data_len EXCEPT ![i] = 0]
              /\ ever_extent' = [ever_extent EXCEPT ![i] = FALSE]
           \/ /\ ~EnableInlineDataModel
              /\ UNCHANGED <<data_kind, data_len, ever_extent>>

\* Materialize: orphan → linked. ALLOCATED + nlink=0 + ~ever_linked
\* transitions to ALLOCATED + nlink=1 + ever_linked=TRUE. Models
\* stm_fs_linkat_anon installing the first dirent for an O_TMPFILE
\* inode + bumping nlink. gen is preserved (the (ino, gen) tuple
\* identity is stable across materialization — POSIX file_handle
\* semantics).
Materialize(i) ==
    /\ EnableOrphanModel
    /\ state[i] = ALLOCATED
    /\ nlink[i] = 0
    /\ ~ever_linked[i]
    /\ nlink'       = [nlink       EXCEPT ![i] = 1]
    /\ ever_linked' = [ever_linked EXCEPT ![i] = TRUE]
    /\ UNCHANGED <<state, gen, history, alloc_event_counter,
                    data_kind, data_len, ever_extent>>

\* FreeAnon: orphan → freed. Explicit cleanup of an unmaterialized
\* O_TMPFILE inode (e.g., process closed the fd without linking).
\* ALLOCATED + nlink=0 + ~ever_linked → FREED. data state cleared
\* (mirrors cascade-free's data-clear branch for the EnableInlineDataModel
\* case). gen preserved so the next AllocReused / AllocAnon at this
\* ino bumps it.
FreeAnon(i) ==
    /\ EnableOrphanModel
    /\ state[i] = ALLOCATED
    /\ nlink[i] = 0
    /\ ~ever_linked[i]
    /\ state' = [state EXCEPT ![i] = FREED]
    /\ \/ /\ EnableInlineDataModel
          /\ data_kind'   = [data_kind EXCEPT ![i] = KIND_NONE]
          /\ data_len'    = [data_len EXCEPT ![i] = 0]
          /\ ever_extent' = [ever_extent EXCEPT ![i] = FALSE]
       \/ /\ ~EnableInlineDataModel
          /\ UNCHANGED <<data_kind, data_len, ever_extent>>
    /\ UNCHANGED <<gen, nlink, history, alloc_event_counter, ever_linked>>

\* --------------------------------------------------------------------------
\* Next.
\* --------------------------------------------------------------------------

Next ==
    \/ \E i \in Inos : AllocFresh(i)
    \/ \E i \in Inos : AllocReused(i)
    \/ \E i \in Inos : Link(i)
    \/ \E i \in Inos : Unlink(i)
    \/ /\ EnableInlineDataModel
       /\ \/ \E i \in Inos, n \in 0..MaxFileLen : WriteInline(i, n)
          \/ \E i \in Inos : TransitionToExtent(i)
          \/ \E i \in Inos : WriteExtent(i)
          \/ \E i \in Inos, n \in 0..MaxFileLen : TruncateInline(i, n)
          \/ \E i \in Inos, n \in 0..MaxFileLen : TruncateExtent(i, n)
    \/ /\ EnableOrphanModel
       /\ \/ \E i \in Inos : AllocAnon(i)
          \/ \E i \in Inos : Materialize(i)
          \/ \E i \in Inos : FreeAnon(i)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Invariants.
\* --------------------------------------------------------------------------

\* Type correctness.
TypeOK ==
    /\ state \in [Inos -> {NEVER_USED, ALLOCATED, FREED}]
    /\ gen \in [Inos -> 0..MaxGen]
    /\ nlink \in [Inos -> 0..MaxNlink]
    /\ alloc_event_counter \in Nat
    /\ \A i \in Inos : history[i] \subseteq (0..MaxGen) \X (0..alloc_event_counter)
    /\ data_kind \in [Inos -> {KIND_NONE, KIND_INLINE, KIND_EXTENT}]
    /\ data_len \in [Inos -> 0..MaxFileLen]
    /\ ever_extent \in [Inos -> BOOLEAN]
    /\ ever_linked \in [Inos -> BOOLEAN]

\* HEADLINE INVARIANT — (ino, gen) uniqueness across all time.
\*
\* For every ino, every (gen, event_id) tuple recorded in history has
\* a UNIQUE gen — meaning that gen was assigned at most once for this
\* ino across the entire execution. A buggy AllocReused that does not
\* bump gen (BuggyReuseNoGenBump) creates two history entries with
\* the same gen but different event_ids, firing this invariant.
\*
\* This is the property that makes (ino, gen) a stable
\* identity-across-time tuple: no fid issued at (X, 5) refers to the
\* same logical inode as a later fid at (X, 5) — UNLESS those event
\* ids actually refer to the same allocation event.
TupleUniqueAllTime ==
    \A i \in Inos :
        \A e1, e2 \in history[i] :
            (e1[1] = e2[1]) => (e1[2] = e2[2])

\* GENERATION COUNTER MONOTONICITY — across the lifetime of an ino,
\* gen never decreases. Combined with TupleUniqueAllTime this gives
\* the strong property: distinct allocations at the same ino have
\* strictly increasing gens.
\*
\* (gen can be bumped only at AllocReused — and the BuggyReuseNoGenBump
\* config violates this directly by producing two history entries
\* with the same gen.)
GenMonotonicAcrossAllocations ==
    \A i \in Inos :
        \A e1, e2 \in history[i] :
            (e1[2] < e2[2]) => (e1[1] <= e2[1])

\* ALLOCATED-IS-IN-HISTORY: every currently-ALLOCATED ino has a
\* corresponding most-recent history entry whose gen matches the
\* current gen[i]. Catches a bug where state flips to ALLOCATED
\* without a history record (e.g., BuggyDoubleAllocate's silent
\* re-issue path that bypasses the history append).
AllocatedReflectedInHistory ==
    \A i \in Inos :
        state[i] = ALLOCATED
            => \E e \in history[i] : e[1] = gen[i]

\* NO TWO SIMULTANEOUSLY-ALLOCATED INODES SHARE A NUMBER. Trivially
\* true given the per-ino state, but pinned anyway as a sanity check.
NoTwoAllocatedSameIno ==
    \A i, j \in Inos :
        (state[i] = ALLOCATED /\ state[j] = ALLOCATED /\ i # j) => TRUE

\* P8-POSIX-3: ALLOCATED ⇔ nlink ≥ 1. Pins the
\* "FREED ⇔ nlink=0 / ALLOCATED ⇒ nlink≥1" decoder invariant
\* (R70 P3-3) at the spec level. BuggyUnlinkLeavesZeroNlink fires
\* this directly: post-decrement to 0, state stays ALLOCATED while
\* nlink is now 0.
\*
\* P8-POSIX-7a-anon refinement: when EnableOrphanModel = TRUE the
\* orphan state (ALLOCATED + nlink=0 + ~ever_linked) is a legitimate
\* intermediate. The reformulated invariant guards only the LINKED
\* portion of the ALLOCATED state. Init sets ever_linked = TRUE for
\* every ino, and pre-7a-anon configs (EnableOrphanModel=FALSE) leave
\* ever_linked at TRUE for every ALLOCATED ino — so the reformulated
\* form reduces to its pre-7a-anon shape (ALLOCATED ⇒ nlink ≥ 1).
\* BuggyUnlinkLeavesZeroNlink still fires (post-decrement: ALLOCATED +
\* nlink=0 + ever_linked=TRUE — antecedent matches, consequent fails).
\* BuggyAllocAnonClaimsLinked fires this too (AllocAnon sets
\* ever_linked=TRUE while nlink stays 0).
LinkedAllocatedHasPositiveNlink ==
    \A i \in Inos :
        (state[i] = ALLOCATED /\ ever_linked[i]) => (nlink[i] >= 1)

\* P8-POSIX-7a-anon: ORPHAN HAS ZERO NLINK. The dual of
\* LinkedAllocatedHasPositiveNlink — orphan inodes (post-AllocAnon,
\* pre-Materialize) MUST have nlink = 0. A buggy AllocAnon that sets
\* nlink=1 + ever_linked=FALSE (or any path that produces ALLOCATED +
\* ~ever_linked + nlink>0) fires this invariant.
\*
\* Vacuously TRUE under EnableOrphanModel = FALSE because Init sets
\* ever_linked = TRUE everywhere + pre-existing actions don't reset
\* it; the antecedent (ALLOCATED + ~ever_linked) never holds.
OrphanHasZeroNlink ==
    EnableOrphanModel =>
        \A i \in Inos :
            (state[i] = ALLOCATED /\ ~ever_linked[i]) => (nlink[i] = 0)

\* P8-POSIX-3: FREED ⇒ nlink = 0. Combined with the above, gives
\* the full FREED ⇔ nlink=0 / ALLOCATED ⇔ nlink≥1 biconditional.
\* Healthy AllocFresh / AllocReused set nlink=1; healthy Unlink
\* drops to 0 only in lockstep with the FREED transition; healthy
\* Link only mutates nlink while state=ALLOCATED. Buggy paths
\* (BuggyLinkResurrectsFreed: bumps nlink while state=FREED is the
\* SOURCE state for the action; the action transitions to ALLOCATED
\* atomically with nlink=1, so this invariant still holds). The
\* invariant fires when an action leaves the (FREED, nlink>0)
\* state visible at any point.
FreedHasZeroNlink ==
    \A i \in Inos :
        (state[i] = FREED) => (nlink[i] = 0)

\* P8-POSIX-3: every ALLOCATED ino has at least one history entry
\* whose gen matches the current gen. This was already pinned by
\* AllocatedReflectedInHistory; the BuggyLinkResurrectsFreed bug
\* fires it because Link doesn't append a history entry — so a
\* resurrected ino has state=ALLOCATED + gen=prior_gen but no
\* history entry recording that allocation event.
\* (Already in the existing invariant set; no new addition needed.)

\* P8-POSIX-5 — data_kind matches state. NEVER_USED / FREED inos
\* have KIND_NONE; ALLOCATED inos have KIND_INLINE or KIND_EXTENT.
\* Catches a bug where Free leaves data_kind as INLINE/EXTENT (storage
\* leak / unreachable-byte loss) or where AllocFresh leaves data_kind
\* at NONE (decoder later refuses to read the inode's data union).
\*
\* Vacuously TRUE when EnableInlineDataModel = FALSE — the flag
\* gating means existing actions UNCHANGED data_kind (it stays
\* KIND_NONE for every ino regardless of state), so the post-state
\* relationship between state and data_kind only carries semantic
\* weight when the inline tracking is on.
DataKindMatchesState ==
    EnableInlineDataModel =>
        \A i \in Inos :
            \/ /\ state[i] # ALLOCATED
               /\ data_kind[i] = KIND_NONE
            \/ /\ state[i] = ALLOCATED
               /\ data_kind[i] \in {KIND_INLINE, KIND_EXTENT}

\* P8-POSIX-5 — INLINE bytes fit in MaxInline. The whole point of
\* inline-data optimization is to keep tiny files in si_inline_data[]
\* and avoid the extent-tree round-trip; if data_len exceeds MaxInline
\* while still claiming KIND_INLINE, the storage-vs-claim drift would
\* corrupt readers (they'd memcpy past si_inline_data's bound).
\*
\* BuggyInlineWriteSpills fires this directly.
\*
\* When EnableInlineDataModel = FALSE: data_kind is always KIND_NONE
\* per the flag-gated existing-action UNCHANGED semantics, so the
\* implication's antecedent is vacuously false everywhere. Still
\* gated explicitly for clarity.
InlineLenBounded ==
    EnableInlineDataModel =>
        \A i \in Inos :
            data_kind[i] = KIND_INLINE => data_len[i] <= MaxInline

\* P8-POSIX-5 — once a file has been EXTENT-backed, it stays EXTENT-
\* backed for the rest of its current allocation. ARCH §11.3.3:
\* "Reverse direction (truncate from large to tiny): the inode could
\*  migrate back to inline, but we skip this — truncation to tiny is
\*  rare, and the code complexity isn't worth it. Once extent-backed,
\*  stays extent-backed."
\*
\* Reset semantics: AllocReused (and AllocFresh of a previously-FREED
\* ino's slot) clears ever_extent[i] := FALSE — a reuse legitimately
\* starts a fresh data lifecycle.
\*
\* BuggyTruncateReinlines fires this when TruncateExtent reverts to
\* KIND_INLINE while ever_extent[i] is still TRUE.
\*
\* When EnableInlineDataModel = FALSE: ever_extent is always FALSE
\* per the flag-gated UNCHANGED semantics, so the implication is
\* vacuously TRUE. Gated explicitly for clarity.
OneWayInlineToExtent ==
    EnableInlineDataModel =>
        \A i \in Inos :
            (state[i] = ALLOCATED /\ ever_extent[i])
                => data_kind[i] = KIND_EXTENT

\* --------------------------------------------------------------------------
\* Bundle.
\* --------------------------------------------------------------------------

Invariants ==
    /\ TypeOK
    /\ TupleUniqueAllTime
    /\ GenMonotonicAcrossAllocations
    /\ AllocatedReflectedInHistory
    /\ NoTwoAllocatedSameIno
    /\ LinkedAllocatedHasPositiveNlink
    /\ FreedHasZeroNlink
    /\ DataKindMatchesState
    /\ InlineLenBounded
    /\ OneWayInlineToExtent
    /\ OrphanHasZeroNlink

=============================================================================
