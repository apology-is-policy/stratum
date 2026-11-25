# 07 — Superblock + sync (commit protocol)

## Purpose

Two tightly coupled modules:

- **`sb`** — the on-disk superblock layout: 4-region label layout,
  4 KiB uberblock structure, commit-ring slot addressing, encode /
  decode / csum. Pure format. No I/O of its own — it speaks bytes
  to `bdev` via sync.
- **`sync`** — the commit-protocol coordinator: drives the 2-phase
  multi-device quorum commit, manages the uberblock ring rotation,
  hosts the per-dataset keyschema, mediates between alloc + pool +
  keyschema during commit and mount.

Together these implement ARCHITECTURE §5 (Superblock + quorum) and
§3.7 (Commit protocol).

## Label + ring layout (sb)

```
Per-device regions (ARCH §5.3.1):

  [ Label 0 | Label 1 |   margin   | Bootstrap pool | data area | Label 2 | Label 3 ]
  ^         ^         ^            ^                ^           ^         ^
  0         256K      512K         1 MiB            bpool_end   end-512K  end-256K

  end = the size the device's roster entry recorded when it joined the
  pool (since v35), not its current size.

Each label (256 KiB) is 63 uberblock slots + 1 mirror slot:

  Slot 0:  ub_gen % slots_per_label == 0 landing pad
  Slot 1:  ub_gen % slots_per_label == 1 landing pad
  ...
  Slot 62: ub_gen % slots_per_label == 62 landing pad
  Slot 63: pool-config mirror (reserved; currently unused)
```

Layout constants (`include/stratum/super.h:103-107`):

| Constant | Value | Meaning |
|---|---|---|
| `STM_UB_SIZE` | 4096 | One uberblock. |
| `STM_LABEL_SIZE` | 256 KiB (64 × UB) | One label region. |
| `STM_LABELS_PER_DEVICE` | 4 | 2 at head, 2 at tail. |
| `STM_UB_SLOTS_PER_LABEL` | 63 | Commit-ring slots. |
| `STM_UB_MIRROR_SLOT` | 63 | Pool-config mirror (future). |
| `STM_DEVICE_MIN_BYTES` | 8 MiB | Minimum device size. |

Ring placement per generation (since v34):

```
slot = gen % STM_UB_SLOTS_PER_LABEL          // 0..62, in every label
```

Each generation's uberblock goes to that slot of all four labels: its
`STM_UB_COPIES` copies (`stm_sb_ub_write_copies`: every copy written,
then one fsync). A device confirms the write only when all four copies
were written and the fsync succeeded (`STM_UB_COPIES_REQUIRED`), so a
successful write leaves no other bytes at the slot, and copies of one
generation differ only after a write that failed. The ring holds 63
generations, about 31 commits (a commit spends a reservation and a
final). Before v34 each generation went to one label (label gen % 4),
one copy, 252 generations; a v34 build reads no earlier pool.

## Uberblock format (4096 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `ub_magic` | `0x324d555441525453` (ASCII "STRATUM2"); every version keeps it here (ARCH section 5.4.1). |
| 8 | 4 | `ub_version` | `STM_UB_VERSION = 35`; `STM_UB_VERSION_MIN_COMPAT = 35`: this build reads its own version only (pools of earlier versions are re-created). Every version keeps it here. |
| 12–20 | 12 | feature flags | `compat` / `ro_compat` / `incompat` (ARCH §5.2). |
| 24 | 16 | `ub_pool_uuid` | Pool identity. |
| 40 | 16 | `ub_device_uuid` | This device's identity. |
| 56 | 8 | `ub_gen` | Monotonic per-commit counter. |
| 64 | 8 | `ub_txg` | Transaction-group counter (currently == gen). |
| 72 | 8 | `ub_roster_hash` | le64 truncation of BLAKE3 over `ub_roster[2048]`. |
| 80 | 2 | `ub_device_count` | Roster size. |
| 82 | 2 | `ub_device_id` | This device's slot in the roster. |
| 96 | 64 | `ub_main_root` | v9+: bptr to the dataset-index tree (`STM_BPTR_KIND_DATASET`). |
| 160 | 64 | `ub_alloc_root` | v7+: points at alloc-roots object (`STM_BPTR_KIND_ALLOC_ROOTS`). |
| 224 | 64 | `ub_snap_root` | v9+: bptr to the snapshot-index tree (`STM_BPTR_KIND_SNAP`). |
| 288 | 64 | `ub_cas_index_root` | CAS index root (future). |
| 352 | 32 | `ub_merkle_root` | Root of the Merkle chain over all metadata. |
| 384–416 | 32 | pool counters | `next_ino`, `next_dataset_id`, `next_snap_id`, `total_blocks`. |
| 416 | 8 | `ub_free_blocks` | Free-block accounting. |
| 424 | 1 | `ub_redundancy_kind` | `NONE / MIRROR / RS / LRC`. |
| 425 | 15 | `ub_redundancy_params` | Mode-specific parameters. |
| 440 | 512 | `ub_key_schema` | Header + bptr into keyschema sub-tree. |
| 952 | 1 | `ub_device_class` | `SSD / HDD / PMEM / ZNS`. |
| 953 | 1 | `ub_device_role` | `DATA / LOG / CACHE / SPARE`. |
| 960 | 2048 | `ub_roster[2048]` | 64 × 32 B roster entries. |
| 3008 | 32 | `ub_merkle_root_salt` | Per-pool random salt. |
| 3040 | 8 | `ub_alloc_root_gen` | Gen at which alloc-root tree was encrypted. |
| 3048 | 64 | `ub_scrub_state` | v8: durable scrub state (P5-durable-cursors). Layout: u8 state + u8 reserved + le16 cursor_device_id + 4 reserved + le64 cursor_start_block + le64 ×6 counters (verified, failed, repaired, unrepairable, ranges_processed, snapshot_cursor). Pack/unpack via `stm_ub_scrub_state_pack/_unpack`. Refreshed at every `sync_commit` if a scrub handle is bound (cb registered via `stm_sync_set_scrub_persist_cb`); otherwise round-trips. |
| 3112 | 8 | `ub_main_root_gen` | v9: gen at which `ub_main_root`'s tree was AEAD-encrypted. Symmetric to `ub_alloc_root_gen`. |
| 3120 | 8 | `ub_snap_root_gen` | v9: gen at which `ub_snap_root`'s tree was AEAD-encrypted. |
| 3128 | 936 | `ub_reserved` | Future fields. |
| 4064 | 32 | `ub_csum` | BLAKE3 over bytes [0, 4064). |

`_Static_assert(sizeof(stm_uberblock) == 4096)` catches accidental
padding on build.

### Roster entry (32 B each, 64-entry fixed array)

```
[0..16)   uuid[16]
[16..24)  size_bytes (le64)
[24..25)  role                 (stm_device_role)
[25..26)  class                (stm_device_class)
[26..27)  state                (stm_device_state)
[27..32)  reserved
```

`ub_roster_hash` (le64 truncation of BLAKE3-256 over the 2048-byte
roster array) provides a quick-check at mount: the in-RAM pool
must have a matching `roster_hash` or sync refuses to proceed
(P5-1 roster-consistency check).

### Block pointer (stm_bptr, 64 B)

```
bp_paddr    (le64)         // (device_id << 48) | block_offset
bp_kind     (u8)           // stm_bptr_kind — INTERNAL / LEAF / EXTENT / ALLOC / SNAP / CAS / KEYSCHEMA / ALLOC_ROOTS
bp_flags    (u8)
bp_reserved1[6]
bp_csum[32]                // BLAKE3-256 over referenced node/extent (AEAD tag for encrypted targets)
bp_reserved2[16]
```

Paddr = (16-bit device, 48-bit offset-in-blocks). Top 16 bits
encode which device holds the block. Helpers:
`stm_paddr_make(dev, offset)`, `stm_paddr_device(p)`,
`stm_paddr_offset(p)`.

### Encoding / decoding

```c
// Encode stm_uberblock struct → 4 KiB buffer. Finalizes ub_csum.
stm_status stm_ub_encode(const stm_uberblock *ub, void *buf, size_t buf_len);

// Decode 4 KiB → struct. Verifies magic, version, csum.
// Returns STM_ENOENT on magic-mismatch (empty slot),
//         STM_EBADVERSION on a version outside MIN_COMPAT..STM_UB_VERSION,
//         STM_ECORRUPT on csum mismatch,
//         STM_ERANGE on size mismatch.
stm_status stm_ub_decode(const void *buf, size_t buf_len, stm_uberblock *out_ub);
```

`ub_encode` writes `ub_csum`, the BLAKE3-256 of bytes [0, 4064), the
bytes before it (every version keeps that, ARCH section 5.4.1).
`ub_decode` rejects `ub_gen == 0` (R14 P3-3 -- zero-gen sentinel) and
accepts versions `STM_UB_VERSION_MIN_COMPAT`..`STM_UB_VERSION`; any other
is STM_EBADVERSION, and `stm_ub_is_newer` and `stm_ub_is_older` tell a
newer or an older build's uberblock from a torn one (below).

### Label scanning

```c
// Compute the byte offsets of the 4 label regions given the device's layout
// size (stm_bdev_layout_bytes: its recorded size once a scan has read it).
stm_status stm_label_offsets(uint64_t dev_size, uint64_t out_offsets[STM_LABELS_PER_DEVICE]);

// The size ub's roster records for ub's own device; STM_ECORRUPT when it
// has no slot for it or the size cannot hold the labels.
stm_status stm_ub_device_bytes(const stm_uberblock *ub, uint64_t *out_bytes);

// Read a single uberblock from (label, slot). Fast-path for targeted reads.
stm_status stm_sb_label_read(stm_bdev *d, uint32_t label, uint32_t slot, stm_uberblock *out);
stm_status stm_sb_label_write(stm_bdev *d, uint32_t label, uint32_t slot, const stm_uberblock *ub);

// Write a generation's uberblock to ring slot `slot` of every label, then
// fsync once. STM_OK only when STM_UB_COPIES_REQUIRED copies (all four)
// were written and the fsync succeeded. The commit path's only writer.
stm_status stm_sb_ub_write_copies(stm_bdev *d, uint32_t slot, const stm_uberblock *ub);

// Scan every (label, slot) on a device, return the single uberblock with
// highest valid ub_gen. Used at mount. Returns STM_ENOENT if no valid UB,
// STM_EIO if no slot decoded and the device failed a read, or if a slot
// that could hold a newer commit still fails after two re-reads (below),
// STM_EBADVERSION at a newer build's uberblock, or when nothing decodes
// and a copy held another build's uberblock. one_device: the device is
// the pool's only one. why: which copy refused (gen for STM_EIO, version
// for STM_EBADVERSION).
stm_status stm_sb_mount_scan_ex(stm_bdev *d, bool one_device,
                                stm_uberblock *out, uint32_t *out_lbl,
                                uint32_t *out_slot, stm_sb_scan_refusal *why);
// The strict rule (one_device false), for a device of a multi-device pool.
stm_status stm_sb_mount_scan(stm_bdev *d,
                              stm_uberblock *out, uint32_t *out_lbl, uint32_t *out_slot);
```

An uberblock a newer build wrote refuses the mount (STM_EBADVERSION): the
magic, a version above `STM_UB_VERSION` and a csum that verifies
(`stm_ub_is_newer`; every version keeps those three fields, and its
uberblocks in the commit-ring slots, where they are: ARCH section 5.4.1).
The scan reads every copy in every commit-ring slot once and, when any
holds one, refuses naming the first in scan order; it refuses too when a
re-read of a copy at slot(best+1) or slot(best+2) finds one, or the
one-device read of slot(best-1)'s copies (made when slot(best+1) does not
settle and best is not a final by its mark). `why` names the copy
and the version, and stratumd says so. The newer build's commits may lie
past every generation this one can read, wherever its layout puts them, so
mounting what it reads would roll the pool back and the claim would
overwrite one of them. The rule is stricter than ZFS's, which judges only
the best uberblock's version: any slot, any generation, read-only mounts
too.

Labels 2 and 3 end at the size the device's roster entry recorded when it
joined the pool (v35, operator vote 161; ARCH sections 4.3.1, 5.3.1). The
scan reads labels 0 and 1 first, whose offsets do not depend on the size,
takes the size their newest uberblock records for the device
(`stm_ub_device_bytes`) and sets the device's layout to it
(`stm_bdev_set_layout_bytes`) before reading labels 2 and 3; every label
offset, the device probe (`sync_device_answers`) and the allocator's data
area use that layout. With no head copy decoding, the layout stays as the
handle had it: the size the caller's roster records once `stm_pool_open`
has run (it lays each live device out at its roster size, and
`stm_pool_add_device` at the size it records for the new device), the
current size on a fresh handle (the fs mount's peek scan). A head
label's offset needs no layout, so labels 0 and 1 are read whatever the
handle's layout is; `stm_pool_open` refuses (STM_EINVAL) a live device
whose recorded size cannot hold a layout, and `stm_sync_create` checks the
primary allocator as `stm_sync_open` does. It refuses:

- `STM_ERANGE` when the recorded size exceeds the device's (`why` names
  both sizes and the head copy): the device's labels 2 and 3 and the end of
  its data area are gone. The layout is set first, so a writer that runs
  anyway (a multi-device pool mounted without the device) aims past the
  device's end, never at its data. `stm_sb_ub_write_copies` writes no
  copy to a device shorter than its layout (`STM_ERANGE`), judged by the
  file's length now (`stm_bdev_current_bytes`, so a cut under an open
  handle counts) and by the handle's size (so a file grown back under a
  handle opened short still counts), and asked again after the copies
  (they never reach the layout's end, so a cut during them shows). Not
  even labels 0 and 1 take a copy: the device never counts toward a
  commit's quorum, and no copy becomes a vote if its tail comes back. A
  one-device pool's commit then fails `STM_ERANGE`, and so does a
  multi-device pool's when that device is the metadata primary, whatever
  the others confirm (OPEN-BUGS (r)): every later open refuses its layout,
  so no generation it misses can be mounted. The handle then wedges. `stm_bdev_write` refuses any write past a device's end
  (`STM_EINVAL`); a file-backed device keeps the size it was cut to. On a pool with one live device `stm_sync_open` returns
  the scan's STM_ERANGE, and the STM_ECORRUPT below, as they are.
- `STM_ECORRUPT` when the uberblock it would mount, or the newest head copy,
  records no valid size or another size than the layout labels 2 and 3
  were read by (`why` names the copy and its generation): every uberblock
  of a device records the same size.

A device that grew keeps its layout and leaves the new space unused; a v34
build read labels 2 and 3 at the new end, where one blank copy settled a
successor slot and rolled the mount back past an acknowledged generation
once the head copies of it were unreadable (F1c review X1).

Its limits. A newer uberblock goes unseen only when every read of every
copy of it fails: each generation has four copies (since v34), so one
failed read no longer hides it. And the rule protects only the builds that
have it: a build before it skips a newer uberblock as torn and mounts the
newest it decodes. A v34 pool gives such a build nothing to decode: format
zeroes all four labels and v34 reads no earlier pool, so its labels hold
v34 uberblocks only, and every earlier build answers STM_EBADVERSION
(nothing decodes and a slot held another version).

An uberblock below `STM_UB_VERSION_MIN_COMPAT` (34: this build reads its
own version only; on-disk breaks are free until the format freezes,
operator decision 2026-11-05, so an earlier pool is re-created) is
skipped like a torn one. When nothing decodes and a copy held one, the
scan refuses STM_EBADVERSION naming the first (`stm_ub_is_older`: the
magic, a version below MIN_COMPAT, a csum that verifies), and stratumd
says the pool was written by an older build and must be re-created.

A copy that fails to decode is skipped: a torn write, or a durable copy
gone bad, which the scan cannot tell apart. Each generation's uberblock is
in slot gen % 63 of every label (`stm_sb_ring_slot_for_gen`, super.h;
every writer puts it there through `stm_sb_ub_write_copies`), so an
uberblock that decodes in another generation's slot came from a
misdirected read or write: it is no candidate, and the copy counts as one
that did not decode (a device holding only such uberblocks answers
STM_ECORRUPT, never STM_ENOENT, the fresh device's answer). Copies of one
generation can differ only after a write of it that failed part-way: the
scan takes the first in label order. Either names an intact tree, because
the fs writes nothing after a failed uberblock write until a remount (a
failed commit wedges the fs, R154; a failed claim fails the mount), and the
remount's claim replaces every copy of its slot. A multi-device pool
carries on past a device whose write failed while quorum holds, and a
library caller's retry can rewrite a generation with new content, so that
device may hold copies of one generation naming different trees: its pick
is only its vote, and the content-quorum check at mount treats a
dissenting device as an orphan, as it did when each generation had one
copy.

A copy the device fails to READ is different: a commit newer than the best
one found can only follow it, at best+1 (best's final when best is a
reservation; otherwise a reservation or a claim, which carry best's trees)
or at best+2 (the final after a reservation at best+1). If the device
cannot read the copies where it would be, mounting the best would roll the
pool back past an acknowledged commit, and the mount's claim at best+1
would overwrite it for good. So the scan settles each copy of such a slot
(below) and the slot with them. The slot settles when
`STM_UB_SETTLE_COPIES` copies hold an older generation of the slot (the
ring came round) or read back blank: a generation this device confirmed
is in `STM_UB_COPIES_REQUIRED` copies, all four, so one copy without it
proves the device never confirmed it (on a multi-device pool the others
may have, by quorum: this device then votes behind). While the slot is not settled and a copy stays
unreadable, the scan refuses (STM_EIO). It settles every copy even once one
settles the slot, since another may hold a newer build's uberblock or a
later generation. A copy that decodes a newer generation moves the best,
and its successors are checked in turn.

Where it refuses depends on the pool. One device writes its generations in
order, each only after the one before is durable (a final waits for its
reservation's barrier). A reservation or a claim carries its predecessor's
`ub_merkle_root` unchanged and an older `ub_repair_log_root_gen`, while every
final stamps `ub_repair_log_root_gen` with its own generation (its mark). So
on a one-device pool (`stm_sync_open` and `stm_fs_mount` pass `one_device`)
the scan refuses at slot(best+1) only when best may be a reservation: neither
its mark nor a copy of best-1 decoding as gen best-1 with other trees (and
none with best's) says final. A claim reads as a reservation, so an
unsettled slot after a claim still refuses (a session that crashed before
its first commit leaves one). It refuses at slot(best+2) only when
slot(best+1) did not settle (a blank copy settles it, since format zeroes
the labels; a copy with no magic and other bytes may be a generation whose
magic rotted, so it does not). A read can come back wrong with no error (all zero
from a lost mapping, another sector's bytes from a misdirected read, a
garble), so before a successor copy counts as anything but valid it is read
again: it counts as blank only after two reads came back all zero, as torn
after two reads came back wrong otherwise (one of them may be zero), and as
unreadable when three reads brought neither two such reads nor a decode (a
failed read counts toward unreadable). Each blank successor copy costs one
more 4 KiB read: four a mount on one device whose ring has not come round.
A device on which nothing decoded at the first read is not blank until its
copies settle the same way: each copy that read back zero, wrong or not at
all is read again (the head labels' before the layout is taken from them,
the tail labels' after the pass), so a read that came back zero once does
not make a device that holds the newest commit a known vote of nothing
(Stratum (r) round 1 F1). A blank device costs one more read per copy,
252, and a dead one (every read failing) two more, 504, since a copy
whose first read failed is read again too: on media that fail slowly the
open waits about three times as long on a dead member, the price of
mounting a ring whose every copy failed its first read and then reads
whole (one read of each answered STM_EIO). A copy that reads zero and
then never again answers STM_EIO, where it answered STM_ENOENT
(Stratum (r) round 2 O1, O2).
A device of a multi-device pool can miss writes while quorum holds (a
FAULTED slot, a failed write), so its generations need not be contiguous
and the newest it confirmed can be in any slot: under the strict rule
every slot must settle, and any that stays unsettled with a copy
unreadable refuses (`why->gen` the first generation past best that slot
can hold); a re-read that finds a newer generation moves best and every
slot is asked again. That costs one more read per blank copy of every
slot: up to 248 (about 1 MiB) on a device whose ring has not come round.
A refusing device is then an unknown vote (the mount flow, step 2), never
a vote for the older generation it read (a stale vote could make a false
quorum). On one device an unreadable copy past best+2 costs nothing. A refusal says which copy
(`stm_sb_scan_refusal`: the generation, label, slot, byte offset and the
best generation read;
`stm_fs_mount_opts.scan_refusal`, filled by the mount's first scan or by
`stm_sync_open_ex`'s own), and stratumd prints it.

With four copies a refusal needs every copy of the successor slot torn
or unreadable, at least one unreadable; one copy per generation (before
v34) refused at one unreadable sector. While it lasts every mount refuses
(a refused mount writes nothing, so nothing rewrites the copies) until the
operator zeroes any one copy of the slot (any will do; the one stratumd
names may refuse writes too), accepting the loss of at most the newest
commit.

The write side pays for it. A label sector that refuses writes fails every
commit whose reservation or final lands on its slot (a commit writes two
generations, so about one commit in 31), and the fs wedges; a mount whose
claim lands there fails once (the next takes that claim as its best: its
other copies landed). A whole label region that refuses writes leaves the
device unmountable read-write, since every reservation and every claim
fails (read-only mounts still work); requiring three copies would ride
through one dead label but needs a same-generation discriminator in the
uberblock, since the first-of-differing pick and the final test trust that
a confirmed write replaced every copy. Transient write errors meet four
writes per uberblock instead of one. In a multi-device pool such a device
fails to confirm and quorum carries on. An explicit opt-in mount that takes the newest readable generation is
enqueued for the operator. (o1c review rounds 1 and 2, F1; btrfs's
`usebackuproot` and ZFS's `zpool import -F` are likewise explicit opt-ins
to a rollback, never a silent one.)

## Commit protocol (sync)

### Multi-device 2-phase (P5-2, quorum-backed)

```
Fresh pool (auth_gen == 0):   1-phase -- write UB at gen=1 to all devices.
                              Its final is stashed before the write, as a
                              reservation is: a failed first commit's retry
                              waits as one does (Phase 1' below).
Subsequent commits:           2-phase, in the CF-4 B order below.

Phase 2: Flush (first; its node writes and fsyncs go into the defer window)
    stm_keyschema_commit(ks, target_gen)      // persist key-schema if dirty
    For each attached alloc in allocs[]:
        stm_alloc_commit(alloc, target_gen)    // persist per-device tree
    stm_alloc_roots_commit(roots, target_gen)  // persist pool-level roots object
    stm_{dataset,snapshot,repair_log,cas}_index_commit(target_gen)
    stm_extent_index_commit_flush(target_gen)  // 9.6-impl-4d: btree_engine FLUSH
                                               //   -> PROSPECTIVE root triple
    stm_inode_index_commit_flush(target_gen)   // 9.6-impl-4b-iii: btree_engine
                                               //   FLUSH -> PROSPECTIVE triple
    stm_dirent_index_commit_flush(target_gen)  // 9.6-impl-4c: btree_engine FLUSH
    stm_xattr_index_commit_flush(target_gen)   // 9.6-impl-4c: btree_engine FLUSH
    compute_merkle_root(... every index csum, incl. extent/inode/dirent/xattr
                            prospective triples ...)
    stm_bootstrap_commit(boot, target_gen)     // RECORDED into the defer
                                               // window (no COW yet)

Phase 1': Reservation (after the flush, before the barrier)
    Content built before the flush: the previous authoritative UB's
    content with gen bumped -- pre-flush roots; the rollback target.
    For each pool device:
        slot = (auth+1) % 63
        build per-device UB (shared bytes + per-device uuid, device_id)
        stm_sb_ub_write_copies(bd, slot, ub)   // all 4 labels; its fsync
                                               // is deferred to the barrier
    Wait for quorum = floor(N/2) + 1 confirmations.
    If sub-quorum: abort; return STM_EQUORUM.
    A retry after any failure past the reservation's build (its write,
    the barrier, the final) reserves at the same gen (current_gen moves
    only when a final is acknowledged), where a quorum may hold the
    first attempt's reservation: it writes the bytes it wrote or tried
    there again (a fail, rejoin or the start of an evacuation moves
    only state bytes, the quorum unchanged). A rebuild records other
    allocator statistics or another roster, and one power loss in its
    write could leave two contents at an acknowledged gen, a device
    each, which no open could pick between (review (ah) round 2 F1).
    A removal or an add changes the quorum, so the sync's
    stm_sync_remove_device, stm_sync_finish_evacuation and
    stm_sync_replace_device_online wait for that retry, refusing
    STM_EBUSY: a retry acknowledged by the new roster's quorum need not
    hold a quorum of the stashed roster, whose own pick then takes the
    first attempt's reservation (one gen below) or orphan final (at the
    acknowledged gen), and an open from that roster claimed over the
    acknowledged commit (review (s)(t)(u)(v) round 4 F1: four devices,
    a removal, the retry's final missed by one of the three left; round
    6 F1: one device added, the rebuilt retry acknowledged by the
    larger quorum, OPEN-BUGS (ak)). A retry that finds the pool's slots
    changed anyway (the pool primitives: a slot the stashed roster names
    removed, or one added) writes nothing, wedges and answers
    STM_EWEDGED. While a retry waits a commit takes no clean-commit
    skip: that skip compares with the last acknowledged final, and a
    rejoin could bring the roster back to it while the failed attempt's
    reservation, carrying the FAULTED state, was the newest on disk
    (round 5 F2: the commit answered STM_OK writing nothing and the
    guard held for good). An engines' finalize failing after the final
    reached quorum wedges the sync, as one on the clean skip does: the
    failed engine stays pending and refuses every later flush, so the
    handle no longer agrees with the pool it wrote.

Barrier
    Stage each bootstrap's one slot-pair COW, then one data barrier per
    device: the reservation's copies, the staged pair and every flushed
    node are durable strictly BEFORE the final UB write. A failed
    barrier aborts the commit.

Phase 3: Final
    Build final UB: post-flush roots + post-flush Merkle.
    Same per-device fan-out as Phase 1.
    Wait for quorum confirmations.
    If sub-quorum: abort; in-RAM state unchanged (rollback UB at auth+1 is durable).
    stm_extent_index_commit_finalize()         // 9.6-impl-4d: adopt the
                                               // flushed extent root, post-UB
    stm_inode_index_commit_finalize()          // 9.6-impl-4b-iii: adopt the
                                               // flushed inode root, post-UB
    stm_dirent_index_commit_finalize()         // 9.6-impl-4c: adopt the
                                               // flushed dirent root, post-UB
    stm_xattr_index_commit_finalize()          // 9.6-impl-4c: adopt the
                                               // flushed xattr root, post-UB

Phase 4: Publish
    auth_gen := auth + 2
    current_gen := auth + 2       // "next commit's final gen"
```

Each commit advances `auth_gen` by 2. Mount-claim advances by 1.

### Extent / inode / dirent / xattr indices — three-phase commit (9.6-impl-4b-iii + 4c + 4d)

The extent, inode, dirent, and xattr modules are all `btree_engine`-
backed (incremental-COW B+tree); each commit is split across
`stm_sync_commit`'s phases. In Phase 2 each `_commit_flush` writes the
dirty nodes to fresh paddrs and yields the PROSPECTIVE root triple —
which feeds `compute_merkle_root` + the final uberblock exactly as a
finished root would. In Phase 3, after the final UB is durable, each
`_commit_finalize` adopts that root + deferred-frees the superseded
nodes. Every error path between flush and finalize runs `_commit_abort`
for every engine whose flush has already succeeded — discarding the
flush(es) and reverting the in-memory tree(s). The abort cascade
(extent flushes first, then inode, then dirent, then xattr):

| failure point                          | abort set                                |
|----------------------------------------|------------------------------------------|
| extent flush                           | (none — self-reverts)                    |
| inode flush                            | extent                                   |
| dirent flush                           | extent + inode                           |
| xattr flush                            | extent + inode + dirent                  |
| anything between xattr flush + UB write | extent + inode + dirent + xattr (all 4) |
| post-UB write (any finalize failure)   | (none — commit point passed; fs wedges) |

A failed `stm_sync_commit` is crash-equivalent — fs.c MUST wedge the fs
(R154 doctrine carry). Every fs wedge wedges the sync as well
(`stm_sync_mark_wedged`, under `s->lock`): from then on `stm_sync_commit`
and the other mutating calls answer `STM_EWEDGED`, so a committer that
checked the fs before the wedge cannot commit after it.

The other way round, the sync wedges itself when a data op's index change
fails part way -- a write, truncate, punch or cold migration that changed
some records and not another, or released some blocks it no longer names
and not another -- and answers `STM_EWEDGED`. Before, it answered the cause (`STM_ENOMEM`),
the fs took that as nothing done, and the next commit took a half change:
a truncate the caller was told had failed read back as zeros. Every wedge
calls the hook `stm_sync_set_wedge_hook` sets, from which `stm_fs` sets its
own flag, so a write after the wedge is refused rather than acknowledged
into a pool that can no longer commit.

The explicit `stm_bootstrap_commit` at the end of Phase 2 is the
durable-bitmap barrier. Every engine's flush set node bits in the
bootstrap bitmap in RAM; that bitmap MUST be made durable strictly
BEFORE the final UB write. Bitmap-then-UB is crash-safe — a crash with
the bitmap durable but the UB stale only leaks the freshly-flushed
nodes (bounded, non-corrupting); the reverse order would let a later
`reserve` re-hand a still-rooted paddr and corrupt the tree
(9.6-impl-4b design §5.2 case A). At 4d the extent module's monolithic
`_commit` internal `stm_bootstrap_commit` is retired from this code
path (the test-only `stm_extent_index_commit` still calls it for
unit-test isolation); the remaining `btree_store`-backed indices
(dataset / snapshot / repair_log / cas) still call `stm_bootstrap_commit`
internally, so the explicit call is redundant-but-cheap for them —
harmless since the call is idempotent at the same gen.

### A data write in pieces

`stm_sync_write_extent` reserves every replica's blocks before it
encrypts. It first asks each device for one run holding the whole
record (data plus tag). When any device has none, the record is written
in pieces, each its own record with its own tag on every replica
(`sync_write_reserve_pieces_locked`): device 0 gives its first free run
of at least 2 blocks, up to the blocks left plus one
(`stm_alloc_reserve_upto`), the piece carries one block fewer of data,
and every other replica reserves the piece's blocks, or a run 1 block
longer where that is all it has. A replica with no run that long is
probed for its first free run, which sets the next try's length, and
device 0 may then take a run 1 block longer than the piece; a piece holds
at least 1 block of data, so a mirror spends at most 3 blocks per block
of data on any device. When the probe finds no run of 2 blocks, or none
shorter than the piece it refused, the write fails. The room is checked
before every piece, so a write refused for want of room, not of a run,
takes no piece. A piece reserved but not yet written goes back free at
once (`stm_alloc_unreserve`); once encrypted, a rollback frees it to
PENDING. The pieces replace the old records in one index step
(`stm_extent_overwrite_pieces`, `14-extent.md`); a failure after the
first record went answers `STM_EWEDGED` and the sync wedges.

### Mount flow

```
1. For each device in pool: stm_sb_mount_scan_ex -> (highest valid ub_gen,
   ub); one_device when the pool has had one device only (a roster of one
   slot: a device a remove left alone may have missed writes while the
   others were there). A device whose scan refuses (STM_EIO; on a pool
   with more than one live device STM_ERANGE and STM_ECORRUPT too) is an
   unknown vote; one that finds no uberblock (STM_ENOENT) votes nothing.
   A FAULTED slot whose device is gone (stm_pool_open admits one with no
   bdev) is an unknown vote too: after a rejoin the roster presented does
   not show, it may have confirmed a commit the others did not. Such a pool
   opens only read-only, every device there opened read-only (STM_EROFS
   otherwise; OPEN-BUGS (ao), (ap)).
   If no device gave a uberblock and one refused, the open answers
   STM_EIO, not STM_ENOENT (an unreadable pool is not a fresh one); a pool
   with one live device answers its STM_ERANGE or STM_ECORRUPT as it is.
2. Compute authoritative gen:
     sort valid gens desc
     auth = gens[quorum - 1]        // kth largest, where k = floor(N/2)+1
   Quorum < k: return STM_EQUORUM.
   Unknown votes (vote 153; quorum.tla Mount, MountHigh): each could be
   as high as any, so the gen a quorum may hold is at most
     ceiling = gens[quorum - unknown - 1]
   ceiling > auth: return STM_EIO, writing nothing. auth could roll back
   a commit those devices and the others above it acknowledged, and the
   claim at auth + 1 would overwrite it. So the no-rollback rule above
   holds for any pool.
   A device read whose newest is more than one gen past auth: return
   STM_EIO, writing nothing. No write puts a device more than one gen
   past a quorum of the roster it was written under (quorum.tla
   NewestNearAuth: the claim and a reservation go to auth + 1, the final
   to auth + 2 only once a quorum confirmed the reservation), so another
   roster moved the pool on (a remove some devices took, after an add
   others did not) or a fault: auth would roll an acknowledged commit
   back. Review round 2 F1: the open from the two-device roster that a
   device which missed an add and a remove still showed mounted gen 1
   under an acknowledged gen 3, and claimed over it.
3. Content pick (OPEN-BUGS (ah); quorum.tla Mount, RingPick):
     Holders: each device read whose newest is auth_gen, and each other
     whose ring slot of auth_gen decodes as that gen (stm_sb_gen_read,
     every copy read until it settles: past auth_gen, or below it after
     a misread in its scan, copies read back zero or one settled beside
     unreadable ones), grouped by byte-equal shared fields; a holder that
     confirmed nothing can only add a group that could have been, never
     take one away. Hidden: a device whose slot of auth_gen
     has a copy that settles torn or unreadable and none decoding as
     auth_gen, moved past auth_gen or below it (a confirmed auth_gen
     torn on every copy leaves the scan's newest below, OPEN-BUGS (ai)).
     (No device reaches the pick more than one gen past auth_gen, step 2,
     so none whose ring came round.) A
     device whose every copy of the slot settles blank or as an older
     lap did not take auth_gen, short of a fault on every copy (a
     confirmed write replaces each), and counts nothing. Review round 1
     F1: counting one blank copy beside damaged ones, or a device below
     auth_gen, as nothing dropped a confirmer of an acknowledged claim,
     and the open mounted the orphan beside it. The price is liveness: a
     write a crash tore on every copy reads the same, and while it could
     hide a confirmer the open refuses STM_EIO; nothing the open does
     rewrites that slot (OPEN-BUGS (ai), vote 152).
     A device that confirmed an acknowledged content at auth_gen keeps
     it in that slot: a later write of auth_gen needs an open below it,
     which this pick and vote 153 exclude, or the retry of the commit
     that wrote it, and a retried reservation is written byte for byte
     again, or nothing when the pool's slots changed between the attempts
     (Phase 1' above), while an acknowledged final is never written
     again.
     A group could have been acknowledged when its holders, the hidden
     devices and the unknown votes reach quorum. One such group is
     canonical (a group of quorum holders is one, and then no other
     is); two: STM_EIO, writing nothing, the hidden devices and the
     unknown votes could decide it; none: nothing at auth_gen was
     acknowledged, and the largest group (the lowest device index on a
     tie) is canonical.
     The fallback's tree is whole (quorum.tla MountIntact): an open
     frees nodes of trees but the one it mounts only once its claim is
     acknowledged (and the trees it never saw are free to it), and a
     node a commit frees goes back only at a commit after its final was
     acknowledged (stm_alloc_commit's free_gen < committed_gen; an
     evacuation step's frees go back sooner, on a device that takes no
     reservation again), so a content that lost nodes sits beside a
     claim acknowledged at
     auth_gen, which could have been, or below a gen acknowledged above.
     Every device read and every copy settled blank or valid, the open
     mounts (MountNotStuck). Before, the check read only the devices whose
     newest was auth_gen: a quorum of them had to agree, and fewer all
     of them; with three devices a claim the next reservation moved
     past, beside an orphan final, or an open's claim that reached one
     device beside a commit's final that reached another, refused
     every open (quorum_ring_buggy.cfg), and with four or more a
     disagreeing minority refused.
     Devices outside the canonical group are orphans (ARCH section 5.8):
     the next commit's writes leave them behind.
4. Roster consistency:
     ub_pool_uuid == pool.uuid
     ub_device_uuid == pool.devices[ub.device_id].uuid
     ub_roster_hash == BLAKE3(pool.roster_bytes)
   Any mismatch -> STM_ECORRUPT.
   Then every live device is laid out at the size the canonical roster
   records: a dissenting device's own copy, or a scan that read no head
   copy, does not place the pool's writes. The primary allocator's data
   area must be the one its own device's layout gives (stm_alloc_check_layout):
   STM_EINVAL when it was opened before the layout was set on a device
   that grew (it would put data on the tail labels), STM_ERANGE when the
   device is smaller than its layout (stm_sync_attach_alloc checks the
   same).
5. MountGenBump + claim:
     claim_gen = auth + 1
     For each device not REMOVED or FAULTED: write a claim UB at claim_gen.
     If quorum confirmed it:
         auth_gen := claim_gen.
         current_gen := claim_gen + 2            // next commit's target
     Else, if no device written failed other than read-only and one
     answered read-only (STM_EROFS; REMOVED and FAULTED slots are not
     written, so not counted): mount read-only, auth_gen stays the durable
     gen (a device that took the claim keeps a copy at claim_gen that no
     quorum makes authoritative).
     Else refuse the open (STM_EQUORUM; a one-device pool, its error).
6. stm_keyschema_load_at(&ub_key_schema.ks_root)
7. stm_alloc_roots_load(ub.ub_alloc_root)
   For each roots-object entry (dev, tree_paddr, csum, tree_gen):
       stm_alloc_load_tree_at(allocs[dev], tree_paddr, tree_gen, csum)
```

`MountGenBump` (sync.tla) is the invariant: every mount must advance
the durable gen past any in-flight gens that could have been written
by a previous process. Prevents crash-recovery nonce reuse.

### The pool to open (OPEN-BUGS (s))

The open takes the pool it is handed and refuses (STM_ECORRUPT) when the
uberblock its pick takes carries another roster. A caller holding only
devices cannot take the roster from one device's newest uberblock: that
can be an orphan of a commit that failed (after a fail, an evacuation or
an add, its roster is not the quorum's), or a device that missed commits
can show an older one.

```c
stm_status stm_sync_scan_roster(stm_bdev *const devs[], size_t ndevs,
                                stm_sb_scan_refusal *why,
                                stm_pool_open_opts *out,
                                uint64_t *out_auth_gen);
```

It writes nothing. Each device's newest uberblock names a roster; with each
roster the open's pick (steps 1 to 3 above, `sync_pick_canonical`, which
the open runs too) runs over the devices, a slot matched to the device
whose newest uberblock carries its device uuid. A slot not REMOVED that no
device matches (absent, blank, or its ring unreadable) is an unknown vote:
a blank device carries no uuid, so the scan never guesses which slot it
is. A roster is the pool's when the uberblock its pick takes carries it;
the roster that uberblock carries is tried too (the pool's roster may be
no device's newest). `out` gets the pool uuid, the device count and the
devices, each bdev the matched handle or NULL, ready for `stm_pool_open`
(an ONLINE slot with no device it refuses, OPEN-BUGS (an)).

A device handed in that is more than one gen past the gen a roster's
pick takes shows that roster is not the pool's. A write of gen g comes
from a session whose authoritative gen was g - 1 (a claim, a reservation),
or g - 2 with the reservation at g - 1 confirmed by a quorum (a final): no
write puts a device more than one gen past a quorum of the roster it was
written under (quorum.tla NewestNearAuth, which models one device set), so
a quorum held the gen below such a device's newest, above the roster's gen,
under the session that wrote it: another roster's quorum (were it this
roster's, its pick would take that gen). The roster is passed over, not answered and not
refused, and an answer then mounts at least that device's gen less one, a
descendant of every acknowledged gen:

- in its pick (step 2), a device it names: a disk a remove or a failed add
  left behind names its old roster, whose pick lands below the pool's
  once the pool moved on (review round 3 F1: that pick's refusal refused
  every scan of such a pool). A REMOVED slot counts nothing in a pick,
  sound only once the remove was acknowledged: after an add devices 0 and
  2 acknowledged at gen 3 and a remove of device 2 whose reservation (gen
  4) reached device 0 alone, the remove's roster's pick takes gen 1 beside
  device 0 at 4 and is passed over (review round 1 F1: it answered the
  roster before the add at gen 1); with device 2 handed in, the add's
  roster answers at 3;
- after its pick, a device it does not name: a device an add brought in
  whose commit's writes missed devices of the old roster. Its final on the
  added device alone (the commit failed, no gen acknowledged above the old
  roster's) leaves the old roster passed over and the larger one answering
  at the reservation's gen, which a quorum of it holds (without this
  filter, STM_EIO: two rosters); its reservation on the added device
  alone, beside a device of the old roster that lost the gen below on
  every copy (read as never confirmed), refuses STM_EIO, no roster left.

Rosters that differ only in FAULTED/EVACUATING/ONLINE give one pick (a
state counts there only as REMOVED or not), so one of them at most is the
pool's. Two that differ in their slots or their REMOVED set can both be
(an add whose reservation the larger roster's quorum holds, its final on
no device handed in: whether the final was acknowledged is unknown, and
each answer is safe in the single-fault model, review round 4 O1):
STM_EIO. The retry of a failed commit reuses its reservation's roster, so
a removal or an add waits for that retry (see the commit above):
otherwise the new roster's final could be acknowledged while the stashed
roster's quorum held the first attempt's writes, two rosters the pool's
with the acknowledgement recorded. An
add a device missed whose final a device holds is decided: the final was
written once the larger roster's quorum confirmed the reservation, and the
smaller roster is passed over. Any other refusal of a roster's pick
refuses the scan: the roster the newest acknowledged commit was made under
may be the one an absent device makes unknown (a crafted witness: devices
0 and 1 hold a removal's acknowledged final at 5 beside the stashed
four-device roster's reservation at 4 on every device; without device 1
that roster's pick takes 4, and passing the refused one over answered it,
review round 4 F2). Hand in every device of the pool you have; a device no
roster read here names cannot vote.
STM_EIO when no roster is the pool's and one was passed over (the later
write no roster read takes: devices holding it were not handed in, or lost
it); STM_EINVAL for handles of two pools or
two of one device; STM_ECORRUPT when no roster is the pool's otherwise, or
for a roster naming a device in two slots (two votes); STM_ENOENT when no
device holds an uberblock, else the first device's own scan refusal.

### Uberblock build helper

```c
static stm_status build_uberblock(stm_sync *s, uint64_t gen, uint16_t target_device_id,
                                   stm_uberblock *ub);
```

Fills in shared bytes (pool_uuid, roster, counters, merkle_root,
bptrs) from sync's in-RAM state, then stamps per-device bytes
(`ub_device_uuid`, `ub_device_id`). Used for both reservation and
final UBs — the two differ only in `ub_gen` and the root bptrs
(pre-flush vs post-flush).

Critical: reservation UB carries the PREVIOUS authoritative UB's
roots (pre-flush state). Final UB carries the NEW roots (post-
flush). The reservation is the rollback target — if Phase 3 fails,
the reservation UB at auth+1 is the pool's durable state.

### Attach APIs for multi-device

```c
stm_status stm_sync_attach_alloc(stm_sync *s, uint16_t device_id, stm_alloc *alloc);

stm_status stm_sync_reserve_mirror(stm_sync *s, uint64_t nblocks,
                                      size_t n_replicas, uint64_t out_paddrs[]);

stm_status stm_sync_mirror_write(stm_sync *s, const uint64_t paddrs[],
                                    size_t n, const void *buf, size_t len,
                                    size_t *out_confirmed);

stm_status stm_sync_mirror_read (stm_sync *s, const uint64_t paddrs[],
                                    size_t n, void *buf, size_t len,
                                    const uint8_t expected_csum[32]);
```

See [08-pool-redundancy.md](08-pool-redundancy.md) for the mirror
protocol details.

### Per-dataset keys

```c
stm_status stm_sync_add_dataset_key       (s, dataset_id, wk_or_janus, &new_key_id);
stm_status stm_sync_add_dataset_key_corvus(s, dataset_id, corvus_path, path_len,
                                           corvus_cfg, &new_key_id);
stm_status stm_sync_rotate_dataset_key    (s, dataset_id, wk_or_janus, &new_key_id, &old_key_id);
stm_status stm_sync_keyschema_sweep       (s, dataset_id, &pruned_count);
stm_status stm_sync_get_dek               (s, dataset_id, key_id, dek_out[32]);
size_t     stm_sync_dek_count             (const stm_sync *s);
```

`wk_or_janus` is a union — exactly one must be non-NULL. `wk` is
the in-process keyfile path; `janus` routes through the remote
unwrap daemon (see [janus](#janus-interaction) below).

`stm_sync_add_dataset_key_corvus` (TLY-A3-keyslot-wrap chunk 5a) is
the corvus provisioning variant of `_add_dataset_key`: it generates a
fresh DEK, seals it via the corvus WRAP verb (`stm_corvus_wrap`) into
an opaque envelope bound to `corvus_path`, stores the envelope as a
`STM_KS_WRAPPER_CORVUS` keyschema slot with the path recorded, and
installs the live DEK. A later mount resolves the slot over the
corvus UNWRAP verb (`sync_unwrap_cb`). Strictly "new dataset" — same
`STM_EEXIST` posture as `_add_dataset_key`.
`stm_fs_create_dataset_corvus` is the fs-layer wrapper; the one-shot
`stratumd --provision-corvus-dataset` CLI is the operator surface
(see [21-stratumd.md](21-stratumd.md)).

### Scrub + device-lifecycle composition

```c
stm_pool  *stm_sync_pool (const stm_sync *s);        // P5-5-α scrub
stm_alloc *stm_sync_alloc(const stm_sync *s, uint16_t dev);

stm_status stm_sync_evacuation_step (s, target, survivor, &old_paddr, &new_paddr);
stm_status stm_sync_remove_device   (s, device_id, redundancy_floor);
stm_status stm_sync_finish_evacuation(s, device_id);
stm_status stm_sync_replace_device_online(s, old_id, new_device, new_alloc, floor, &new_id);
```

See [08-pool-redundancy.md](08-pool-redundancy.md).

## Lock composition

`sync` owns an internal `pthread_mutex_t`. Global lock order (from
`pool.h`):

```
POOL  (rwlock)   ← outer
SYNC  (mutex)
ALLOC (mutex)
```

Every sync API that touches pool state wraps the critical section:

```c
stm_pool_lock_shared(s->pool);      // POOL OUTER
pthread_mutex_lock(&s->lock);       // SYNC INNER
... do work ...
pthread_mutex_unlock(&s->lock);
stm_pool_unlock_shared(s->pool);
```

Safe-removal wrappers (`stm_sync_remove_device`,
`stm_sync_finish_evacuation`) hold pool.wrlock + sync.lock
atomically so add / attach / commit / detach composes in one step.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `sync.tla` | Single-device four-phase commit (legacy; superseded by quorum.tla in P5-2 but kept for spec-to-code clarity). `DoFlush / DoFinal / DoPublish`, `MountGenBump`. |
| `quorum.tla` | Multi-device 2-phase + mount-claim, each device's ring kept slot by slot, the claim written device by device. `QuorumSafety`, `AuthoritativeMono`, `CommitAtomic`, `OrphansNotAuthoritative`, `ContentQuorumAtGen`, `LiveCoordTargetValid`, `QuorumDurability`, `MountGenBumpMulti`, `MountAtAuthoritative`, `MountKeepsPublished`, `MountNotStuck`. See [10-specs](10-specs.md) for the configs and their counts; `quorum_buggy.cfg` (`IdempotentRetry=FALSE`) reproduces R14 P1 content-divergence at spec level. |
| `merkle.tla` | Merkle chain integrity: tamper of any covered node changes `ub_merkle_root`. |

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_sb` | 62 | Encode / decode roundtrip; csum tamper rejected; magic tamper -> STM_ENOENT; version tamper -> STM_EBADVERSION; zero-gen rejected; label offsets; label_read / label_write; mount_scan picks highest valid; the bytes every version keeps (magic, version, the csum's domain, read without `stm_ub_csum`; an uberblock of those fields alone is a newer build's); a newer build's uberblock refuses the mount and the refusal names its slot (best+1, one of the kept fields alone, two in other slots naming the first, re-reads at best+1 and best+2, the one-device read of best-1; a torn one and an older one do not); every generation in all four labels: the write puts every copy and fails when one fails, a generation is found by any copy, one copy settles a slot, the first of differing copies is taken (in the first pass and when re-reads find them), a later copy beats a blank one before it, a refusal names the first unreadable copy, the one-device final call needs no copy of best-1 with best's trees, an older build's pool is named; the layout (v35): a grown device's tail labels are read where it joined (an acknowledged generation found there, a later write lands there, the new end stays blank; control: not grown), a device smaller than recorded refuses naming both sizes (a newer build's head copy refuses first), with no head copy the tail is read at the current size, and an uberblock recording another size, or none, refuses (a roster counting more than its 64 slots too); a handle laid out at a size no layout can have still reads its head labels.; a device shorter than its layout (cut under the handle, cut before the open, grown back under a handle opened short, cut while its copies are written) takes no copy, read-only answers STM_EROFS; vote 153: on a multi-device pool any slot unsettled with a copy unreadable refuses, naming the first generation past best it can hold (a device that missed gens: one device mounts best past it; a copy failing once is re-read and moves best across the gap; one copy unreadable costs nothing); round 1: a move asks the slots behind it again (one unreadable between the old best and the new refuses), a ring whose every copy read back zero once is settled and its newest found by either rule (a blank ring so read still answers STM_ENOENT), a grown device's head copies read back zero once are settled before the tail is laid out, and with the head blank the tail's copies so read are settled after the pass; round 2: copies that read back zero once and then fail answer STM_EIO, on a device holding a commit and on a blank one; a newer build's uberblock behind a zero read refuses, named from the head and, the head blank, from the tail; copies whose first read failed are read again and the newest found. OPEN-BUGS (ah): `stm_sb_gen_read` takes gen's uberblock from any copy, each read again until it settles (a first read back zero or failed), the first of differing copies in label order; takes gen's copy beside one blank or holding another lap; answers STM_ENOENT when every copy settles blank or as another lap, and STM_EIO when a copy does not settle or settles torn and none decodes as gen (unreadable, torn, zero then failing, one copy blank beside three unreadable or torn); a newer build's uberblock in any copy refuses, behind a zero read too, `why` naming the copy and its version. |
| `test_sync` | 50 | Single-device commit + remount; MountGenBump; alloc-root tree encoded under correct key; version boundary refusals; every ring write lands in all four labels, a mount finds the newest generation by any copy, and no one unreadable label hides a commit; an allocator opened before the scan on a device that grew is refused, writing nothing (control: not grown); a device smaller than its recorded size refuses the open (STM_ERANGE), writing nothing; a pool made on a device larger than its roster records is laid out at the recorded size (its uberblock copies at the recorded tail, its data area below them), and an allocator made before stm_pool_open is refused; a one-device layout refusal keeps its status (STM_ECORRUPT) and names its copy.; a one-device pool's image cut under the open pool fails the next commit STM_ERANGE and is not regrown. |
| `test_sync_multi` | 89 | 3-device quorum roundtrip; 1-of-3 device loss tolerated; sub-quorum refused (STM_EQUORUM); orphan-ahead-of-quorum ignored; content-quorum tested; alloc-roots indirection; v5/v6/v7 version refusals (the v5 test exercises one prior version; the decode accepts only `STM_UB_VERSION_MIN_COMPAT`..`STM_UB_VERSION`, and a newer build's uberblock refuses the pool); mirror(2) + mirror(3) roundtrips + tampered-replica fallback; reserve refuses NONE profile; attach_alloc arg validation; RO pool refuses write ops; wedge refusal; keyschema idempotent commit produces byte-identical UBs; replace_device_online resume from step-3 commit failure; same-uuid-different-alloc refused; slot-0 spoofing refused; multi-retry converges; **commit succeeds with one FAULTED device** (R21 P1); replace-claim blocks concurrent mutators on the claimed slot via sync-wrapper bypass-closed (R23 P3-4).; a replace whose rollback cannot remove the new slot wedges and answers the wedge; a newer build's uberblock on one device refuses the open and names its slot; attach refuses an allocator whose data area runs past its device's layout, and one on a device smaller than its layout; a dissenting device's own recorded size does not place the pool's writes on it; a device truncated below its recorded size gets no uberblock, keeps that size through the pool's open and commit, and never counts toward a commit's quorum; a read-only open of a pool holding a REMOVED slot, or a FAULTED one, mounts read-only and reads a block committed before (control: read-write, the same roster opens and claims); a commit that two FAULTED slots of three leave short of quorum fails STM_EQUORUM; vote 153: a commit acknowledged by two devices of three, one of them unreadable at the next open, refuses STM_EIO and writes nothing (control: healthy, it mounts; with the third device holding it too, the unknown vote cannot change the gen and it mounts), an attach over a bitmap open could not confirm reconciles it before any reserve (every node of the device's tree held after; a commit and a remount after), and a device removes left alone keeps the strict scan (a slot unreadable past best+2 refuses); (r): the metadata primary cut under the open pool fails the commit STM_ERANGE and wedges (control: another device cut, the commit is acknowledged and the next open mounts it); round 1: a device whose every ring copy read back zero once is settled and the open mounts the acknowledged gen over it; two devices at auth_gen, fewer than quorum, disagreeing (an orphan final and the acknowledged claim, four devices) refuse STM_EQUORUM by either device order, with or without reuse (control: they agree and the claim mounts); an attach reconciles a confirmed bitmap too (the bootstrap holds the tree's nodes alone after); both attach tests run on a tree of three nodes; round 2: a device whose every ring copy reads back zero once and then fails is an unknown vote, and the open refuses STM_EIO and writes nothing; an attach of an alloc carried over from an earlier session leaves its bootstrap as it was, the frees its commits left pending kept for the commit that releases them, and the commits and a remount after keep every node of the tree (control: reopened blank, those frees are reclaimed). OPEN-BUGS (ah): three devices, every one online, the claim a device moved past beside an orphan final mounts (it refused every open), and refuses STM_EIO, writing nothing, when that device's slot is torn or its scan refuses, and so when its newest is more than one past (67 and 68 alike: review round 2 F1); an orphan final and an open's claim each on one device mount the lower index's, and so with a device moved past whose slot was never written; a device lagging at gen 3 with its slot of 5 blank counts nothing and its own uberblock is no candidate; a confirmer of the acknowledged claim whose slot of 5 is torn (its scan reads 4) or, moved past 5, reads one copy back zero and three unreadable is counted hidden: STM_EIO, nothing written, where the open mounted the orphan or failed STM_ECORRUPT (controls: the slot intact, the one zero copy beside three holding the claim, and the slot its scan read back zero, so newest 4, decoding after: a holder below auth_gen, the claim mounts); a newer build in the slot read past the scan refuses STM_EBADVERSION, `why` naming the copy, its version and the device's newest; four devices, the minority test now mounts the claim from the moved-on devices' slots, with one of them torn too, and refuses STM_EIO with both, nothing written; three distinct contents at auth_gen mount device 0's (the largest group, the lowest index on a tie), where R14 P1 refused; a commit retried after its final failed writes its reservation's bytes again (an allocator reserve between the attempts; the first commit after an open, whose phase 2 sweeps the frees the session before it left pending; a device failed between the attempts; a first attempt whose reservation write itself failed), and one power loss in that write, tearing one device, leaves a pool that mounts the reservation's trees (control: nothing between the attempts, the bytes already the same); a device added between the attempts (stm_pool_add_device) makes the retry write nothing and wedge, the two-device pool reopening at the reservation (review (s)(t)(u)(v) round 6 F1: the retry rebuilt, and acknowledged by the three-device quorum it rolled back under an open from device 0's roster). OPEN-BUGS (t): device 2 failed, rejoined, and gens 4 and 5 acknowledged without device 0: an open from device 0's roster with device 2 gone counts it an unknown vote and refuses STM_EIO, writing nothing, where counting it nothing mounted gen 3 and claimed over device 1's gen 4 (controls: device 2 there, read, STM_ECORRUPT; device 1's roster, gen 5 mounts); a pool whose FAULTED device is gone opens read-only, reads a block mirrored before and refuses a commit, and read-write refuses STM_EROFS, writing nothing (OPEN-BUGS (ao)); the gone slot refuses rejoin, the start of an evacuation and an allocator (STM_ENODEV); a device there whose allocator was not attached is not removed (STM_EBUSY) nor called drained by an evacuation step (STM_EBUSY) (control: attached, its tree empty, it is removed); a device never attached, for which the pool records no tree, an evacuation step calls drained (STM_ENOENT) and the evacuation finishes; a create over a gone FAULTED slot refuses STM_ENODEV (control: the device there, it creates). OPEN-BUGS (s): `stm_sync_scan_roster`: after a failed commit whose reservation only device 0 holds (another roster), the open from device 0's roster refuses STM_ECORRUPT, and the scan answers the quorum's roster in either order of the handles, the pool opening from it at the last acknowledged gen and committing; after a rejoin device 0 missed it answers device 1's roster at gen 5, and with device 2 gone refuses STM_EIO; a gone FAULTED slot is answered with no device and the pool opens without it read-only (read-write STM_EROFS); around an add, reached by every device it answers the three-device roster; with device 1 missing it the two-device roster (its pick at gen 1 beside device 0 at 3) is passed over and the three-device roster answers at 3 (it refused STM_EIO, two rosters), the plain open from device 1's two-device roster refusing STM_EIO and writing nothing (device 0 exactly two past: it mounted gen 1 and claimed over gen 3; the bound loosened to two passes it), and without device 2 STM_EIO (the three-device roster's pick refuses: answering the two-device one mounted gen 1 under an acknowledged gen 3); with the add's final written nowhere both rosters are the pool's, STM_EIO; a roster no device's newest names, which the pick takes, is tried and answered; STM_EINVAL for no handles, too many, a NULL one, no out, one device twice and two pools (each beside its control; the other pool's device alone scans as its one-device pool), the first device's refusal when every ring is unreadable, STM_ENOENT for blank devices; a roster naming one device in two slots refuses STM_ECORRUPT (it would give that device two votes); after an add devices 0 and 2 acknowledged and a remove whose reservation reached device 0 alone, the scan without device 2 refuses STM_EIO (device 0's gen 4 is more than one past the answer; without that bound it took the two-device roster at gen 1), and with it the add's roster answers at 3, the remove's reservation unacknowledged (control: every write landed, the remove's roster at 5 opens); the plain open from device 1's own newest roster (two devices, gen 1) refuses STM_EIO, writing nothing (review round 2 F1: it mounted gen 1 and claimed over device 0's gen 4; control: every write landed, device 1's roster is the remove's and mounts 5); a one-device pool that took two devices and removed one, device 0 missing gens 2 to 5 and device 1 gen 5, refuses STM_EIO without device 2 (the remove's roster passed over in its pick; device 1, which device 0's one-device roster does not name, holds gen 4) and with it answers the add's roster at 3 (control: every write landed, the remove's roster at 5); a disk a failed add left behind, attached, names the two-device roster: once device 0 is two past it that roster is passed over and each scan answers the one-device pool, opened and committed three times (it refused every scan after the first); a two-device pool that acknowledged gen 3 and took a third device whose reservation reached it alone, device 1 having lost gen 3 on every copy, refuses STM_EIO: the added device's gen 4 is more than one past the answer's gen 2 (control: device 1 kept gen 3, the two-device roster at 3 opens); an add's final on the added device alone (the commit failed) leaves the two-device roster passed over and the three-device one answering at 2, its reservation (review round 4 F3); a crafted pool where devices 0 and 1 hold a removal's final at 5 beside the four-device roster's reservation at 4 on every device refuses STM_EIO without device 1 (the removal's roster's pick refuses on that unknown vote; passing it over answered the four-device roster at 4, review round 4 F2), and with device 1's slot of 5 blank answers that roster at 4 (control). Round 4 F1: a removal (stm_sync_remove_device, stm_sync_finish_evacuation) while a failed commit waits for its retry refuses STM_EBUSY and changes nothing; after the retry, its final missing device 2, it removes, and the scan and an open from device 2's own roster mount the acknowledged 5 (that open refuses STM_ECORRUPT, writing nothing, when the evacuation's start between the attempts put another roster in 5); the pool primitive's removal there makes the retry write nothing, wedge and answer STM_EWEDGED (control: the same removal after the retry, and the next commit rebuilds); round 5: with a fifth device added and devices 3 and 2 removed through the pool between the attempts, the retry, rebuilding for the larger count, still writes nothing and wedges (control: the same after the retry, and it commits); a wedged handle's remove and finish answer STM_EWEDGED; a device failed, a commit failed, the device rejoined (the roster the last acknowledged final's again): the next commit writes the retry and the removal proceeds, the pool opening at 5 (it answered STM_OK writing nothing, and the guard held); round 6: stm_sync_replace_device_online refuses STM_EBUSY while a failed commit waits for its retry, adding nothing, and after the retry the same replace completes. |

## Status

- [x] Uberblock encode / decode / csum / magic / version.
- [x] Label offsets + label read / write / mount_scan.
- [x] Single-device 4-phase commit (P3).
- [x] Multi-device 2-phase quorum commit (P5-2).
- [x] Content-quorum agreement check (R14).
- [x] Mount-claim + MountGenBump.
- [x] Attach-alloc + reserve-mirror + mirror_write + mirror_read.
- [x] Per-dataset key add / corvus-provision / rotate / sweep / get_dek.
- [x] Device-lifecycle composition (evac / remove / replace / fail / rejoin).
- [x] Wedge + read-only guards.
- [x] Per-pool rwlock composition (P5-4b-ii-β).
- [x] Scrub accessors (`stm_sync_pool`, `stm_sync_alloc`).
- [ ] **RS / LRC redundancy profiles**: `STM_RED_RS`, `STM_RED_LRC`
      refused with `STM_ENOTSUPPORTED` at create-time. Post-P5 work.
- [ ] **Async commit fan-out**: sync ops today. `block.h` async API
      is wired but sync_commit doesn't use it. Phase 6+ perf pass.
- [ ] **Pool-config mirror** in slot 63: reserved, unused.
- [ ] **Dynamic metadata primary**: sync hard-codes device 0 as the
      metadata primary (keyschema lives on device 0's bootstrap,
      alloc-roots lives on device 0). Cannot remove device 0 today
      (`STM_ENOTSUPPORTED`). Refactor deferred to post-P5.

## Janus interaction

The `janus` module (`src/janus/`, `include/stratum/janus.h`) is the
remote key-wrap daemon client. Every key operation in sync can
route either through `wk` (in-process keyfile) or `janus` (9P
over Unix socket to a separate daemon process). The two paths
are mutually exclusive per call — `sync_create` / `_open` /
`_add_dataset_key` / `_rotate_dataset_key` all take both and refuse
unless exactly one is non-NULL.

Janus provides stronger security (the daemon can hold the wrap
SK in a separately-privileged process; the filesystem never sees
it in plaintext). Keyfile is simpler (good for local tests).

Not in scope for this reference — see ARCHITECTURE §7.7.3 for the
daemon design.

## Known caveats

- **First commit is 1-phase** (`auth == 0`). Subsequent commits are
  2-phase. The asymmetry is unusual but intentional — there's no
  pre-flush state to preserve on rollback for a fresh pool. A failed
  first commit's retry rebuilds its final (the flush runs again) but
  waits as a reservation's retry does: removal and replace refuse
  STM_EBUSY, and a retry under changed slots wedges (review (s)(t)(u)(v)
  round 7 F1: an add or a removal between the attempts let the retry be
  acknowledged under the new roster while an open from the old one took
  the first attempt's final at gen 1 and claimed over it).
- **Per-device tree gens can diverge** when `stm_alloc_commit`
  short-circuits on a clean tree (R7c P2-5). `ub_alloc_root_gen`
  (v3→) and per-entry `root_gen` in the alloc-roots object
  (v6→v7) carry the correct gen for AEAD decryption at mount.
- **Content-quorum check is byte-level** on shared UB bytes — any
  non-determinism in `build_uberblock` (e.g. uninitialized padding)
  would cause false divergence. Tests pin that UBs are byte-
  identical across devices at the same gen.
- **The scan refuses two rosters** (`stm_sync_scan_roster`, OPEN-BUGS
  (s)): around an add or a remove whose commit's reservation some devices
  hold and whose final none does, both rosters can be self-consistent and
  nothing on disk says which one was acknowledged: STM_EIO. Any other
  refusal of a roster's pick refuses the scan, a stale roster's too: a
  removed disk handed in names the roster from before its remove, and a
  device of that roster thrown away since is an unknown vote there
  (OPEN-BUGS (as)). Hand in every device of the pool you have, or open
  with a roster known otherwise (the open refuses STM_EIO, writing
  nothing, when a device it reads is more than one gen past the gen it
  takes).
- **Mount-claim requires quorum** — if a majority of devices are
  down or corrupt at mount time, mount fails. ARCH §5.11 describes
  a future emergency-mount mode that accepts sub-quorum with admin
  opt-in; not yet implemented.
- **`ub_reserved[1016]`** is the migration reserve for future
  format fields. Adding a field carves from this region, bumps
  `STM_UB_VERSION`, and gates the v(n)→v(n+1) migration at mount.
