----------------------- MODULE metadata_nonce -----------------------
(***************************************************************************)
(* Metadata-node AEAD nonce uniqueness under multi-device (ARCH §4.4.3 +   *)
(* §7.4.1, CLAUDE.md "Nonce uniqueness" invariant).                         *)
(*                                                                           *)
(* Authored 2026-04-24 after R15 F1 (P0) found a real nonce-reuse bug in   *)
(* the P5-3c impl. This spec RETROACTIVELY captures the invariant the bug  *)
(* violated; going forward, any refactor to the metadata-node encryption  *)
(* path should be checked against this spec FIRST per CLAUDE.md's spec-    *)
(* first policy.                                                            *)
(*                                                                           *)
(* The bug:                                                                 *)
(*                                                                           *)
(*   Per ARCH §6.1, each device in a Stratum v2 pool has its own allocator *)
(*   tree, stored as AEAD-encrypted nodes in that device's bootstrap pool. *)
(*   Node encryption uses AEGIS-256 with nonce = paddr || gen || pool_uuid *)
(*   (see v2/src/btree_store/crypt.c:build_nonce, 32 bytes). The metadata *)
(*   key is pool-wide (shared across every device's tree).                  *)
(*                                                                           *)
(*   stm_bootstrap returns paddrs with the device_id bits hardcoded to 0   *)
(*   (v2/src/bootstrap/pool.c:152, unit_to_paddr). Without an explicit     *)
(*   device-id stamp at the alloc layer, two devices' bootstraps produce  *)
(*   IDENTICAL paddr values — device 0's first reserve and device 1's     *)
(*   first reserve both return paddr=(0, head_offset). When both trees     *)
(*   commit at the same gen under the shared metadata_key, the AEAD nonce *)
(*   (paddr, gen, pool_uuid) collides between their first tree-node       *)
(*   writes.                                                                *)
(*                                                                           *)
(*   AEGIS-256 is nonce-respecting: same (key, nonce) encrypting different *)
(*   plaintexts is catastrophic — XOR of the two ciphertext keystreams     *)
(*   recovers the plaintext XOR, and from there plaintexts + forge tags.   *)
(*   This breaks the confidentiality AND authenticity of EVERY metadata    *)
(*   node in the pool.                                                      *)
(*                                                                           *)
(* The fix (R15 F1, commit dd8a275):                                        *)
(*                                                                           *)
(*   alloc's store_reserve vtable stamps the owning alloc's device_id into *)
(*   the top 16 bits of the bootstrap-returned paddr BEFORE handing it to *)
(*   btree_store. store_write/_read/_free validate the paddr's device_id   *)
(*   matches, and strip it back to (0, offset) for the device-ignorant    *)
(*   bootstrap API. Every per-device tree-node nonce is now unique.        *)
(*                                                                           *)
(* This spec models both variants (buggy + fixed) via a BOOLEAN constant   *)
(* DeviceStampPaddrs, matching the quorum.tla IdempotentRetry pattern that *)
(* caught R14 P1 at spec level.                                             *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Devices,           \* finite set of device ids, e.g. {1, 2, 3}
    MaxCommits,        \* bound on distinct metadata-node writes per device
    MaxPaddrsPerDev,   \* bound on the per-device paddr stream
    DeviceStampPaddrs  \* BOOLEAN: TRUE = P5-3c fix, FALSE = pre-fix bug

ASSUME /\ Devices # {}
       /\ Cardinality(Devices) >= 1
       /\ MaxCommits \in Nat \ {0}
       /\ MaxPaddrsPerDev \in Nat \ {0}
       /\ DeviceStampPaddrs \in BOOLEAN

(***************************************************************************)
(* A nonce is the (paddr, gen) pair passed to build_nonce.                 *)
(*                                                                           *)
(* paddr values:                                                            *)
(*   - Without device-id stamping (bug): bootstrap paddr is just the       *)
(*     offset in the bootstrap pool. Two devices' first reserves both     *)
(*     return 1, second both return 2, etc.                                 *)
(*   - With device-id stamping (fix): paddr = d * MAX_OFFSET + offset     *)
(*     (approximating the real (d<<48) | offset encoding). Different      *)
(*     devices stamp different top-bits, so paddrs never collide across   *)
(*     devices.                                                              *)
(*                                                                           *)
(* MAX_OFFSET is the offset-upper-bound (MaxPaddrsPerDev+1). Stamping     *)
(* d*MAX_OFFSET keeps per-device paddrs disjoint: device d uses offsets   *)
(* [d*MAX_OFFSET .. d*MAX_OFFSET + MaxPaddrsPerDev-1].                     *)
(***************************************************************************)

MaxOffset == MaxPaddrsPerDev + 1

StampPaddr(d, local_paddr) ==
    IF DeviceStampPaddrs
    THEN d * MaxOffset + local_paddr
    ELSE local_paddr

(***************************************************************************)
(* State.                                                                    *)
(*                                                                           *)
(*   next_local_paddr[d] — monotonic per-device paddr stream (matches      *)
(*                          stm_bootstrap's in-order issuance; fresh        *)
(*                          reserves only — no reuse within the spec).     *)
(*   writes               — the set of metadata-node writes recorded as   *)
(*                          tuples <<stamped_paddr, gen>>. Two writes       *)
(*                          with identical nonce records are a violation.  *)
(*   per_dev_writes[d]    — count of writes on device d, bounded by       *)
(*                          MaxCommits so TLC terminates.                  *)
(*   current_gen          — shared commit gen. Simplification: models a   *)
(*                          single commit advancing gen → every device     *)
(*                          writes at that gen before the next BumpGen.   *)
(***************************************************************************)

VARIABLES
    next_local_paddr,     \* [Devices -> Nat]
    writes,               \* SUBSET [paddr: Nat, gen: Nat]
    per_dev_writes,       \* [Devices -> 0..MaxCommits]
    current_gen           \* Nat

vars == <<next_local_paddr, writes, per_dev_writes, current_gen>>

MaxGen == MaxCommits + 1   \* one gen beyond the max commit

(***************************************************************************)
(* Init.                                                                     *)
(***************************************************************************)

Init ==
    /\ next_local_paddr = [d \in Devices |-> 1]
    /\ writes           = {}
    /\ per_dev_writes   = [d \in Devices |-> 0]
    /\ current_gen      = 1

(***************************************************************************)
(* Actions.                                                                  *)
(*                                                                           *)
(* ReserveAndWrite(d) — device d reserves its next local paddr, stamps   *)
(*   it (subject to DeviceStampPaddrs), and records a metadata-node write *)
(*   at the current commit gen. Models one tree-node write during the     *)
(*   commit phase.                                                          *)
(*                                                                           *)
(* BumpGen — commit boundary: advance current_gen. Subsequent reserves   *)
(*   reuse paddr offsets (deferred-free at a later gen is outside this   *)
(*   model's scope; the real bootstrap's pending-free doesn't recycle    *)
(*   within a single gen, matching the in-spec invariant).                *)
(***************************************************************************)

ReserveAndWrite(d) ==
    /\ per_dev_writes[d] < MaxCommits
    /\ next_local_paddr[d] <= MaxPaddrsPerDev
    /\ current_gen <= MaxGen
    /\ LET local == next_local_paddr[d]
           stamped == StampPaddr(d, local)
           \* Tag the write record with device_id so two separate
           \* writes from different devices at the same (paddr, gen)
           \* don't set-dedup into a single element. Without the tag,
           \* TLC's set semantics silently hides the exact violation
           \* this spec is meant to catch.
           w == [device |-> d, paddr |-> stamped, gen |-> current_gen]
       IN  /\ writes' = writes \union {w}
           /\ next_local_paddr' = [next_local_paddr EXCEPT ![d] = local + 1]
           /\ per_dev_writes' = [per_dev_writes EXCEPT ![d] = @ + 1]
    /\ UNCHANGED current_gen

BumpGen ==
    /\ current_gen < MaxGen
    /\ current_gen' = current_gen + 1
    /\ UNCHANGED <<next_local_paddr, writes, per_dev_writes>>

Next ==
    \/ \E d \in Devices : ReserveAndWrite(d)
    \/ BumpGen

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

TypeOK ==
    /\ next_local_paddr \in [Devices -> 1..(MaxPaddrsPerDev + 1)]
    /\ per_dev_writes   \in [Devices -> 0..MaxCommits]
    /\ current_gen      \in 1..MaxGen
    /\ writes \subseteq [device: Devices,
                        paddr: 0..((Cardinality(Devices) + 1) * MaxOffset),
                        gen: 1..MaxGen]

(***************************************************************************)
(* The load-bearing invariant. For every pair of distinct metadata writes *)
(* in the `writes` set, their (paddr, gen) nonces must differ. Under      *)
(* DeviceStampPaddrs=FALSE, this invariant is violated as soon as two    *)
(* devices both write their first tree node at the same gen (both produce*)
(* local_paddr=1 → stamped_paddr=1 → identical nonce (1, gen)).          *)
(*                                                                           *)
(* Under DeviceStampPaddrs=TRUE, stamped paddrs are disjoint per device  *)
(* (device d uses offsets [d*MaxOffset .. d*MaxOffset + MaxPaddrs]),     *)
(* so nonces stay unique across devices.                                   *)
(***************************************************************************)

NonceUniqueness ==
    \A w1, w2 \in writes :
        (w1 # w2) => (w1.paddr # w2.paddr) \/ (w1.gen # w2.gen)

Invariants ==
    /\ TypeOK
    /\ NonceUniqueness

=============================================================================
