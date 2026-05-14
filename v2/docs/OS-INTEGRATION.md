# Integrating Stratum into Your Operating System

A practical guide for OS authors adopting Stratum as the first-class root filesystem of their distribution.

This document is the integration manual. It assumes you've read:

- [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) — design intent, including unimplemented work.
- [`docs/ROADMAP-V2.md`](../../docs/ROADMAP-V2.md) — phased plan; what's shipped vs queued.
- [`REFERENCE.md`](REFERENCE.md) — as-built per-subsystem reference with `file:line` citations.

If you're skim-reading: start at §3 "Choosing an integration mode," then §4 "Boot lifecycle," then §17 "Common pitfalls." Everything else is depth-on-demand.

---

## 1. Why Stratum

Stratum aims to be a first-class peer of ZFS and btrfs — not a demo, not a hobby project, a production-grade COW filesystem that a POSIX-compatible OS can be built on. It also pioneers in seven areas the state of the art has left underdeveloped:

1. **Formally verified sync + crash-safety protocol** — TLA+ specifications of the three-phase sync, allocator invariants, and AEAD nonce machinery. No mainline filesystem has this.
2. **Post-quantum encryption by default** — ML-KEM-768 + XChaCha20-Poly1305 hybrid wrap keys. Out of the box, not a flag.
3. **Content-defined extent boundaries** — rolling-hash chunking at the extent layer. Shift-resistant dedup for real-world workloads (VMs, container images, backups). Roadmap.
4. **Lock-free metadata path** — Bε-tree message-buffer model paired with MVCC readers. Roadmap.
5. **Merkle-rooted metadata integrity** — every metadata write is bound into a Merkle chain; offline tampering is cryptographically detectable.
6. **Tiered storage with learned migration** — beyond heuristic hot/cold. Roadmap.
7. **io_uring-native, zero-copy write path** — designed for 2026+ NVMe, not retrofitted from POSIX block I/O. Roadmap.

What this means for your OS: today (v2.x) you get a production-grade COW + PQ-encrypted + Merkle-integrity + tiered + snapshot-capable POSIX filesystem with a comprehensive admin surface. The novel angles ship over the v2.x cycle.

---

## 2. The integration surface — what you actually bind to

Stratum exposes three concurrent ABIs:

| ABI | Form | Stability | Audience |
|---|---|---|---|
| **9P2000.L wire** | TCP / Unix socket | Stable; Linux v9fs already speaks it | Kernel mounts, network mounts |
| **libstratum-9p (C)** | `libstratum_9p_client.a` + `include/stratum/9p_client.h` | Stable per ARCH §10.2 | Userland tools, OS init, language bindings |
| **In-process C library** | `libstm_fs.a` + headers under `include/stratum/` | UNSTABLE — bound to current UB version | Embedded use only; the bypass-9P path |

**Recommendation**: always go through 9P. The in-process bypass is reserved for the case where your process is provably the sole writer AND you accept the UB-version churn risk. For an OS root-fs you want the 9P route — multi-process sharing is universal.

The 9P transport is `stratumd`: one process per pool, bound to a Unix socket. It accepts concurrent client connections (each with its own fid namespace per [`reference/20-9p.md`](reference/20-9p.md)). Optionally a second Unix socket exposes the `/ctl/` admin synthetic FS (see §7).

---

## 3. Choosing an integration mode

| Mode | When to pick it | What you pay |
|---|---|---|
| **Linux v9fs kernel mount over Unix socket** | Production root-fs on Linux today | Mature; one syscall round-trip per VFS op |
| **FUSE userland mount via libstratum-9p** | Prototype OS; need to debug 9P traffic | Two syscall trips per op; fine for bring-up, not for prod |
| **Direct libstratum-9p in your shell/tools** | Tools, file managers, AI agents talking to Stratum directly | One IPC trip; bypasses VFS entirely |
| **Kernel-native stratum module** | Long-term first-class integration | A serious port — 30-50% of `v2/src/` (sync, alloc, crypto) needs kernel adaptation; ~10-20 KLOC effort |
| **`/ctl/`-only — keep your existing FS** | Your OS uses ZFS/btrfs but wants Stratum's admin surface and observability story | Negligible — link libstratum-9p and dial the `/ctl/` socket |

Most distributions starting fresh today should land in the **Linux v9fs kernel mount over Unix socket** row. It gets you to a working `mount /` against Stratum in a week, not a year. The kernel-native port can come later when you're ready to commit a serious filesystems team.

**Stratum on macOS/BSD**: same options minus the kernel-native module. v9fs-equivalents exist (macOS has had 9P kernel support intermittently); the safer route on those platforms is FUSE-T or macFUSE bridging libstratum-9p.

**Stratum on Plan 9 (or 9front)**: 9P is the native protocol. You skip the v9fs adapter and `mount /n/stratumd <pool>` directly. This is the cleanest integration story and is part of why Stratum picked 9P2000.L over Plan 9-flavored 9P2000 (the `.L` dialect carries POSIX semantics over the wire — symlinks, mode bits, xattrs, advisory locks).

---

## 4. The boot lifecycle

Canonical boot sequence for a Stratum-rooted system on Linux:

```
1. Firmware → bootloader → kernel + initramfs (this part is unchanged).
2. initramfs:
   a. Find the pool device(s).         e.g. /dev/disk/by-partuuid/<…>
   b. Locate the .key sidecar.         e.g. on an ESP partition, or TPM-sealed
   c. Unwrap the master key.           Argon2id / TPM-unseal / hardware token
   d. fork() stratumd:
        stratumd --pool /dev/<…> \
                 --key /run/stratum.key \
                 --fs-listen  /run/stratum/fs.sock \
                 --ctl-listen /run/stratum/ctl.sock
   e. Wait until /run/stratum/fs.sock binds.   ← stratumd readiness signal
   f. mount -t 9p \
        -o trans=unix,version=9p2000.L,uname=root,access=user,msize=8388608 \
        /run/stratum/fs.sock /sysroot
   g. Pivot root into /sysroot.
   h. Pass the .key fd into the new namespace (or shred the in-memory copy).
3. systemd / init takes over inside /sysroot.
   - stratumd survives as a service (already running, now reparented to PID 1).
   - Optionally launch slate as a system or per-user daemon (see §17).
4. Long-running:
   - Periodic snapshot via /ctl/datasets/<id>/create-snapshot.
   - Periodic scrub via /ctl/pools/<uuid>/scrub-trigger.
   - Tier migration via /ctl/pools/<uuid>/migrate-policy-step.
```

### initramfs implementation notes

- **Don't re-mount the device into the initramfs's `/`** — Stratum needs `stratumd` to own the block device exclusively. The initramfs holds the device long enough to fork stratumd, then never touches it again.
- **`.key` lifetime**: between unwrap and mount-success, the unwrapped key sits in RAM. Use `mlock(2)` + `MADV_DONTDUMP`. After mount succeeds, the key has been consumed by stratumd; shred your initramfs copy with `explicit_bzero`.
- **Pool-readiness probing**: stratumd binds its FS socket as the last init step (after super-block validation, allocator load, Merkle root verification). The presence of the socket is the OK signal — don't try to read the socket before it binds.
- **Failure modes the initramfs must surface**: `STM_ECORRUPT` (Merkle mismatch — refuse to boot, drop to recovery shell), `STM_EBADTAG` (AEAD MAC failure — refuse to boot), `STM_EBADKEY` (wrong .key — prompt for re-unlock), `STM_EWEDGED` (fs marked wedged at last unmount — refuse to boot, run `stratum fs verify` from recovery).

### systemd unit example (post-pivot)

```ini
# /etc/systemd/system/stratumd.service
[Unit]
Description=Stratum filesystem daemon
After=local-fs.target

[Service]
Type=notify
ExecStart=/usr/bin/stratum serve \
    --pool /var/lib/stratum/pool.stm \
    --key  /run/stratum.key \
    --fs-listen  /run/stratum/fs.sock \
    --ctl-listen /run/stratum/ctl.sock
NotifyAccess=main
LimitNOFILE=infinity
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

For the initramfs-launched root-fs case, you typically don't want systemd to manage stratumd's lifecycle (PID 1 inherited it). Instead use a `RemainAfterExit=yes` unit that just asserts liveness via a `/ctl/version` read.

### fstab semantics

```
# <source>                <target>  <type>  <options>                                 <dump>  <pass>
/run/stratum/fs.sock      /         9p      trans=unix,version=9p2000.L,msize=8388608  0       0
/run/stratum/fs.sock      /home     9p      trans=unix,version=9p2000.L,aname=home     0       0
```

The second line uses `aname=home` to bind the `/home` subvolume of the same pool via a separate 9P attach — this is the namespace composition described in [`reference/20-9p.md`](reference/20-9p.md) (Tbind/Tunbind / aname routing).

### Quorum-aware boot for multi-device pools

Stratum pools can span devices (mirror or raidz-shape; see `specs/quorum.tla`). On boot, if a device is missing, stratumd will:

- **Refuse to mount** if quorum is impossible (e.g., a 2-of-3 mirror with 2 missing).
- **Mount degraded** if quorum is possible (e.g., 2-of-3 with 1 missing). Subsequent writes go to the surviving devices; resilver kicks in on rejoin.

Surface this in your boot UI. The Stratum admin tool (`stratum fs status`) returns a 3-state verdict (Healthy / Degraded / Faulted) — wire it into your bootloader's pre-mount banner if you want a clear "your pool is degraded" message before the user types their passphrase.

---

## 5. Encryption: key delivery, rotation, and the sidecar contract

Stratum is **post-quantum encrypted by default**. Per-extent AEAD is XChaCha20-Poly1305. Per-pool master-key wrap is hybrid X25519 + ML-KEM-768. There is no plaintext mode — the security floor is "encrypted at rest, MAC-verified on read."

### The `.key` sidecar is a separate factor

The pool data lives in one or more block devices (or files). The wrap key lives in a separate `.key` sidecar. **NEVER propose embedding the .key into the pool header.** The separability IS the security boundary: an attacker who exfiltrates the pool device without the .key has ciphertext with no path to plaintext that doesn't break ML-KEM-768. An attacker with the .key but no pool device has nothing useful.

This means your OS's installer must, at install time:

1. Generate (or import) a master key.
2. Write the wrapped key blob to a `.key` sidecar.
3. **Decide where the sidecar lives** — see options below.

### Key-delivery options

| Mechanism | When | Trust root |
|---|---|---|
| **Passphrase + Argon2id** | Single-user laptop; user-typed at boot | Brain |
| **TPM-sealed (sealed against PCRs)** | Server, fleet | Measured boot chain (UEFI + bootloader + kernel + initramfs) |
| **TPM + PIN** | Fleet with operator presence | TPM ∧ short PIN (rate-limited by TPM) |
| **Hardware token (YubiKey / FIDO2 hmac-secret)** | High-assurance laptop | Physical possession + touch |
| **Network keyserver (Tang + Clevis)** | Datacenter; locked to network presence | Network membership |
| **Split (Shamir / k-of-n)** | Disaster recovery; HSM-protected | k administrators present |

The Stratum codebase doesn't enforce any one of these — it just consumes a wrapped-key blob at mount time. The OS author picks the policy.

### Per-dataset keys

Each dataset has its own DEK derived from the master via HKDF. This means you can give a workload (a container, a VM, a guest user account) access to a specific dataset's DEK without exposing the master. **Key rotation is per-dataset and is a planned-roadmap operation** — per `docs/ARCHITECTURE.md`, the rotation primitive will re-encrypt extents lazily (on-read or on-scrub).

### Kernel keyring integration (Linux)

After mount, drop the unwrapped key into the kernel keyring (`add_key(2)`, type `user`, session keyring). Subsequent stratumd reconnections (e.g., after `stratumd` restart) read from the keyring instead of the on-disk sidecar. This minimizes the unwrapped-key footprint on disk to the initramfs-only window.

### What you must NOT do

- **Don't store the .key on the same block device as the pool**, even in a separate partition, unless that partition has independent encryption (LUKS / FileVault). The threat model is "device offline-exfiltrated"; if both halves travel together you've burned the second factor.
- **Don't write the unwrapped key to a swap-able tmpfs without `mlock`.** Hibernation file leaks happen.
- **Don't expose the .key file path through any client-visible RPC**, even for "convenience." It belongs to the boot path only.

---

## 6. POSIX surface — what's shipped, what's deferred

Stratum v2.x ships a comprehensive POSIX surface. The full inventory:

### Shipping in v2

| Surface | Status | Reference |
|---|---|---|
| Inodes (allocate / free / gen monotonicity) | LIVE | [`reference/16-inode.md`](reference/16-inode.md) |
| Dirents (create / lookup / unlink / readdir cursor stability) | LIVE | [`reference/17-dirent.md`](reference/17-dirent.md) |
| Extended attributes (xattrs) | LIVE | [`reference/18-xattr.md`](reference/18-xattr.md) |
| File seals (`F_SEAL_*`) | LIVE | P8-POSIX-7a-seals |
| Advisory locks (`flock` / `fcntl` F_OFD_SETLK) | LIVE | [`reference/19-locks.md`](reference/19-locks.md) |
| `statx` + `utimensat` + ctime/mtime/btime discipline | LIVE | P8-POSIX-7a-statx |
| `name_to_handle_at` + `open_by_handle_at` | LIVE | P8-POSIX-7c |
| `copy_file_range` | LIVE (whole-file MVP) | P8-POSIX-10b |
| `reflink` (FICLONE) | LIVE (single-dataset) | P8-POSIX-10 |
| `rename` + `RENAME_EXCHANGE` + `RENAME_WHITEOUT` + `RENAME_NOREPLACE` | LIVE | P8-POSIX-9 |
| `fallocate`: PUNCH / COLLAPSE / INSERT / ZERO / UNSHARE | LIVE | P8-POSIX-7b |
| Symlinks + hard links (incl. `linkat(2)` by ino) | LIVE | P8-POSIX-8 |
| `O_TMPFILE` orphan inodes + materialize | LIVE | P8-POSIX-7a-anon |
| `posix_fadvise` (WILLNEED → promote-hot, DONTNEED → migrate-cold) | LIVE | P8-POSIX-7e |
| Inline data optimization (≤ 100 bytes) | LIVE | P8-POSIX-5 |
| Snapshots (create / delete / hold / release / iterate) | LIVE | [`reference/snapshot.tla`-derived] |
| Atomic snapshot rollback | LIVE for v1 carry; v2 surfacing in progress (SWISS-6 v1.1c) | |

### Deferred (roadmap)

| Surface | Why deferred | Timeline |
|---|---|---|
| Cross-dataset `reflink` | Needs matching encryption keys | Architectural; gated on rekeying primitive |
| io_uring-native zero-copy write path | Architectural rewrite of the write path | v2.x mid-cycle |
| Content-defined extent boundaries | Rolling-hash dedup; novel angle #3 | v2.x mid-cycle |
| ACLs beyond POSIX 0777 bits (NFSv4 / POSIX.1e draft) | Niche; xattr-stored if needed | On request |
| FS-verity (Merkle-protected file readback at VFS layer) | Stratum already does this at extent layer; need API surface | v2.x late |
| `inotify`/`fanotify` event delivery to kernel | 9P doesn't tunnel kernel events natively; needs Stratum extension | v2.x late |
| Direct I/O (`O_DIRECT`) | Architectural; conflicts with extent encryption | Likely never via the encrypted path |

If your OS depends on one of the "deferred" surfaces, plan for it: either contribute the work upstream, or wrap a degraded behavior (e.g., emulate inotify via polling) until the upstream surface lands.

### Surfaces an OS author often wants to know about specifically

- **`mmap` with MAP_SHARED**: handled at the FUSE/v9fs layer, with the usual VFS page-cache semantics. Concurrent mmap+write is consistent because reads observe the post-flush extent (the dirty buffer's drain is synchronous from the writer's PoV).
- **Hard-link semantics**: Stratum allows hard links to regular files only. POSIX-compliant; same as ext4.
- **Case sensitivity**: byte-for-byte, like ext4/btrfs/ZFS-on-Linux. Case-folding is not on the roadmap.
- **Quotas**: per-dataset reservation + refquota are roadmap; not in v2.0.
- **Anonymous mappings**: Stratum doesn't manage process anonymous memory — that's the kernel's mm subsystem. Stratum's `O_TMPFILE` is for filesystem-backed anonymous storage (the orphan-inode design from P8-POSIX-7a-anon).

---

## 7. The `/ctl/` admin synthetic filesystem

Stratum's admin surface is itself a synthetic 9P filesystem. Your OS init, your observability stack, your CLI tools, your provisioning tool — all of them dial the `/ctl/` socket and read/write virtual files.

### Topology (cumulative as of v2.x)

```
/ctl/
├── version                        — daemon build info (RO, world-readable)
├── state                          — fs counter dump (RO, world-readable)
├── events                         — append-only audit log (RO, admin-gated)
├── pools/
│   └── <pool-uuid>/
│       ├── status                 — Healthy / Degraded / Faulted (RO)
│       ├── scrub                  — scrub state + counters (RO)
│       ├── scrub-trigger          — start / pause / resume / abort (RW, admin)
│       ├── metrics/prometheus     — Prometheus exposition (RO, world-readable)
│       └── devices/
│           └── <device-id>/status — per-device state (RO)
├── datasets/
│   └── <dataset-id>/
│       ├── properties             — effective properties (RO)
│       ├── set-property           — set a property (RW, admin)
│       ├── snapshots/<snap-id>    — per-snapshot info (RO, admin)
│       ├── create-snapshot        — admin verb (RW, admin)
│       ├── delete-snapshot        — admin verb (RW, admin)
│       ├── hold-snapshot          — admin verb (RW, admin)
│       └── release-snapshot       — admin verb (RW, admin)
├── debug/
│   └── allocator-state/<device-id>   — diagnostic dump (RO, admin)
└── admin/
    ├── peer                       — caller credentials (RO, admin)
    └── clear-events               — clear audit log (RW, admin)
```

### Why this shape

- **Composable with shell tools**: `cat /ctl/pools/<uuid>/status`, `echo start > /ctl/pools/<uuid>/scrub-trigger`, `grep failed /ctl/events` — works with no special tooling.
- **Programmable by AI agents**: a script or LLM that can read/write files can administer Stratum, no SDK needed.
- **Authentication via SO_PEERCRED**: stratumd reads the connecting process's UID and gates admin verbs server-side. No tokens, no certs in the local path.
- **Audit log is first-class**: every admin verb writes a line to `/events`; logged before the verb fires, surfaced via `/events`'s append-only RO read. Failure modes (verb refused, verb errored) also log.
- **Prometheus exposition is built in**: scrape `/ctl/pools/<uuid>/metrics/prometheus` from Prometheus, Grafana, or your monitoring vendor of choice. No sidecar exporter.

### Integration patterns

- **OS install-time**: write a `/ctl/datasets/.../set-property` for each tunable (`recordsize`, `compression`, `dedup-policy`, etc.) before populating the dataset.
- **System updates**: take a `/ctl/datasets/<root-id>/create-snapshot` before unpacking the upgrade. If the upgrade fails (boot loop, integrity check), rollback to the snapshot via `/ctl/datasets/<id>/rollback` (SWISS-6 v1.1c forward-noted).
- **Periodic scrub**: cron-equivalent issues `echo start > /ctl/pools/<uuid>/scrub-trigger` weekly. Monitor via `/ctl/pools/<uuid>/scrub`.
- **Per-app observability**: containers / services can have their own read-only fid on `/ctl/datasets/<their-dataset-id>/properties` to introspect their own quota / hot-tier residency / etc. without admin rights.

See [`reference/22-ctl.md`](reference/22-ctl.md) for the full kind table and the trust-boundary discipline that every read and write path inherits.

---

## 8. Snapshots for atomic system upgrades

This is one of the most underrated wins of running on Stratum: **transactional OS upgrades are nearly free**.

### The shape

```
1. Snapshot the root dataset.
     echo "before-upgrade-$(date +%s)" > /ctl/datasets/<root-id>/create-snapshot
2. Apply the upgrade in-place.
     dnf upgrade (or apt, or however your distro does it).
3. Reboot.
4. Boot succeeds:
     Hold the snapshot for N boots, then auto-release per the retention policy.
   Boot fails (kernel panic / init refuses to start):
     Bootloader picks the previous kernel; userland rollback verb fires.
     echo <snap-id> > /ctl/datasets/<root-id>/rollback-snapshot
```

### Why this is better than overlay-based transactional updates

- **No layered FS overhead.** OSTree / Silverblue / Image-Based-Linux all build on top of a base filesystem with overlays or bind mounts. Stratum's COW + snapshot is the layering primitive — your "deployment" is just a snapshot identifier.
- **Rollback is constant-time.** Snapshot rollback rewrites a single dataset table pointer (architecturally; see the snapshot.tla spec). No "downgrade by reinstalling old packages" loop.
- **All data, not just system files.** Snapshots cover every byte of the dataset, so a botched config change in `/etc` is rolled back atomically with the bad upgrade.

### Considerations

- **Hold the snapshot until the boot succeeds.** Use `/ctl/datasets/<id>/hold-snapshot` to prevent admin or retention from deleting the rollback target before you've confirmed success.
- **Snapshot creates flush the dirty buffer first.** A snapshot during a hot write loop will block briefly. Schedule snapshots when the system is quiescent OR accept ~hundreds of ms of write stall.
- **Snapshot names are line-oriented; sanitize user input.** Names with control bytes are refused server-side (R99 P2-1 doctrine), but your UI should refuse them client-side too.

---

## 9. Storage tiers

Stratum supports per-extent tier tagging: HOT (default, on NVMe-class storage) and COLD (on slower bulk storage). Migration between tiers is a separate operation; the read path transparently handles either.

### Admin verbs (via `/ctl/`)

| Verb | Effect |
|---|---|
| `migrate-to-cold` (per ino) | Demote one file's extents to COLD |
| `migrate-policy-step` (per dataset) | Run one heuristic pass — promote-aged + demote-untouched |
| `promote-to-hot` (per ino) | Promote one file (forced; used by `fadvise(WILLNEED)`) |
| `promote-policy-step` (per dataset) | Run one heuristic pass — promote-recent |

### `posix_fadvise` integration

- `POSIX_FADV_WILLNEED` → `stm_fs_promote_to_hot` on the inode.
- `POSIX_FADV_DONTNEED` → `stm_fs_migrate_to_cold` on the inode.

These are advisory and don't block. Userspace tools (a video editor before a render; a build system before a hot recompile loop) can use them as application-level performance hints with no Stratum-specific code.

### What's not in v2.x

The **learned tier policy** (novel angle #6) ships as a separate roadmap chunk. Until then, the policy steps above are heuristic: aged-LRU for demote, recent-access for promote. The interface (`/ctl/datasets/<id>/migrate-policy-step`) is stable; the policy behind it evolves.

---

## 10. Scrub and integrity

### Two integrity layers

- **Per-extent AEAD**: every block has a Poly1305 MAC. Every read verifies. Tamper detection at byte granularity.
- **Per-metadata-block Merkle chain**: every metadata block (inode, dirent, xattr, btree node) is bound into a Merkle chain rooted at the superblock's `merkle_root`. Offline tampering of any metadata block is detected at mount or scrub.

### Scrub semantics

`echo start > /ctl/pools/<uuid>/scrub-trigger` walks every allocated extent and every metadata block:

- Reads + verifies MAC (data) or Merkle binding (metadata).
- On mismatch: increments the unrepairable-error counter; surfaces via `/ctl/pools/<uuid>/scrub`.
- For redundant pools (mirror / raidz): repairs by reading from another copy and rewriting the corrupted side.

### What an OS author should wire up

- **Trigger weekly scrubs by default.** A systemd timer + a `/ctl/pools/<uuid>/scrub-trigger start` write. Most systems don't realize they have silent bit-rot until they migrate; weekly scrub catches it early.
- **Alert on first non-zero scrub error.** Don't wait for the second. Stratum's MAC verification means a single bit flip in a block causes a MAC mismatch — there's no plausible "benign" first error.
- **Refuse to boot on unrepairable scrub errors.** The verdict from `/ctl/pools/<uuid>/status` is "Faulted" when an unrepairable error has been seen. Treat that the same as a wedge.

---

## 11. Observability

### Prometheus

`/ctl/pools/<uuid>/metrics/prometheus` is a text-exposition endpoint. Wire your Prometheus scraper to it:

```yaml
scrape_configs:
  - job_name: stratum
    static_configs:
      - targets: ['unix:/run/stratum/ctl.sock']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __metrics_path__
        replacement: /ctl/pools/<uuid>/metrics/prometheus
```

(A small Unix-socket-to-HTTP adapter is the typical pattern since Prometheus' native scraper speaks HTTP; the `node_exporter` `textfile_collector` is another option for batch-export.)

### Available metrics (as of v2.x)

- Pool-level: `stratum_pool_total_bytes`, `stratum_pool_used_bytes`, `stratum_pool_allocated_blocks`, `stratum_pool_free_blocks`, `stratum_pool_state` (enum).
- Scrub-level: `stratum_scrub_state`, `stratum_scrub_extents_total`, `stratum_scrub_extents_scrubbed`, `stratum_scrub_errors_repaired`, `stratum_scrub_errors_unrepairable`.
- Per-device: `stratum_device_state`, `stratum_device_bytes_total`, `stratum_device_bytes_used`.
- Per-dataset (planned, S5-PRE-B): `stratum_dataset_used`, `stratum_dataset_referenced`, `stratum_dataset_compressratio`.

### Events

`/ctl/events` is an append-only audit log:

```
2026-05-13T08:14:02Z create-snapshot dataset=1 name=before-upgrade-1715587442 result=ok snap_id=42
2026-05-13T08:15:11Z scrub-trigger pool=<uuid> verb=start result=ok
2026-05-13T08:15:11Z scrub-state pool=<uuid> state=running
2026-05-13T09:02:33Z device-fault pool=<uuid> device=2 reason=mac-mismatch extents=1
```

Tail it like syslog. Forward to your SIEM. The format is line-oriented ASCII; control bytes in user-supplied strings (snapshot names, dataset names) are refused at the source, so log-injection attacks are closed.

### OTLP (forward-note)

Native OTLP exposition is deferred to a sidecar translator. The Prometheus endpoint is the v2.x baseline.

---

## 12. Crash recovery

Stratum's sync protocol is three-phase per [`specs/sync.tla`](../specs/sync.tla) (carry from v1; see `docs/STRATUM.md` §7 for the legacy write-up). The invariants:

- **`disk ss_gen > fs->gen`** at all times post-mount. AEAD nonces are unique across the volume's lifetime because every write encrypts under `(paddr, write_gen=fs->gen)` and those pairs are globally unique.
- **Sync is three-phase**: reservation (G+1, pre-flush root) → flush at gen G → final (G+2, post-flush root). `fs->gen` advances by 1 per sync.
- **Quorum** for multi-device: see [`specs/quorum.tla`](../specs/quorum.tla). On mount, if a winning uberblock can be assembled from the available devices, mount; otherwise refuse.
- **Merkle verification on mount** (default OFF in v2.x; toggleable to ON via `STM_FS_MOUNT_VERIFY_MERKLE` — performance-tuning lever): walk the entire metadata Merkle chain and verify. Slow on large pools; recommended for periodic scrub instead.

### What your OS sees after kernel panic

1. Pool device(s) come back online.
2. stratumd starts (initramfs or service).
3. stratumd reads both uberblocks, picks the winner per quorum.
4. Replays any in-flight commit per the three-phase recovery.
5. Bumps `ss_gen` past `fs->gen` to seal off the prior mount's nonce space.
6. Binds the FS socket.

There is no `fsck` step. The crash-safety protocol is the recovery — if it succeeds, the mount succeeds; if it fails, the pool is `STM_ECORRUPT` and your OS should drop to a recovery shell.

### Force-fsck escape hatch (forward-note)

A "force replay from snapshot" verb is on the roadmap for the catastrophic case (one uberblock is also corrupted; recover from a held snapshot). v2.0 ships without this — operators rely on backups for the worst case. If your OS distribution targets enterprise SLAs, plan to contribute or wait for this.

---

## 13. ABI stability and forward-compat

### What's stable

- **`libstratum-9p` C ABI**. The functions in `include/stratum/9p_client.h` are versioned by major number. Breaking changes get a major bump + 2-version sunset.
- **9P2000.L wire dialect + Stratum extensions** (Tsync, Treflink, Txattrwalk, etc.). Wire-level breakage gets a major bump + capability-flag negotiation at Tversion.
- **`/ctl/` URI tree.** New kinds are additive; the qid kind:8 encoding has 248 free values. Removing a kind or changing its semantics is a major version event.
- **`stratum` command-line tool's user-facing flags.** Same compatibility envelope as `git` — flags don't get reused for new meanings.

### What's NOT stable

- **The on-disk format.** Bound to `STM_UB_VERSION` (the UB-version constant). Each format-breaking change bumps the version. Downgrades require explicit conversion or a backup-restore. Track the table in [`reference/00-overview.md`](reference/00-overview.md).
- **`libstm_fs` internal C ABI** (the in-process bypass). Don't link this from out-of-tree code.
- **TLA+ spec internals.** Specs evolve as the formal model improves; if you depend on them, pin to a snapshot.

### UB-version migration

When `STM_UB_VERSION` bumps:

1. The new `stratum fs format` writes the new version.
2. The new `stratum fs mount` reads either the old or the new version (mount-side compat is maintained for at least one major version).
3. An explicit `stratum fs upgrade` rewrites the on-disk metadata to the new format. This is usually a re-walk-and-rewrite of the relevant trees; can be done online.
4. Old `stratum` binaries refuse to mount the new format.

Plan your distro's upgrade story around this. The Stratum codebase makes the migration straightforward; your OS just needs to schedule it.

---

## 14. Performance tuning levers

| Lever | Default | What it does |
|---|---|---|
| `msize` (Tversion negotiation) | 8 MiB | Per-9P-message ceiling. Higher = fewer round-trips for big writes. v9fs kernel client tunable. |
| `iounit` (per-Tlopen) | min(msize-headers, 64 KiB chunks for write) | Per-fid optimal I/O size hint. |
| `STM_FLUSH_DIRECT_THRESHOLD_BYTES` | 1 MiB | Writes ≥ this bypass the dirty buffer, hit the extent layer directly. |
| `STM_FLUSH_INODE_CAP_BYTES` | 8 MiB | Per-inode buffered-write ceiling. Inode flushes when exceeded. |
| `STM_FLUSH_GLOBAL_CAP_BYTES` | 256 MiB | Global buffered-write ceiling. Forces flush_all when exceeded. |
| `recordsize` (per-dataset property) | 128 KiB | Target extent size. Larger = better compression + lower metadata overhead; smaller = lower write amplification. |
| `compression` (per-dataset property) | zstd-1 | Compression algorithm. `off` for already-compressed workloads (video, encrypted backups). |
| `scrub-priority` | normal | `low` for less interference with foreground I/O. |

Per-inode lock granularity (P9.5-PARALLEL-3) means concurrent writes on disjoint inodes scale linearly with cores. Concurrent writes on the *same* inode serialize on the per-inode mutex — design hot workloads to spread across inodes (e.g., one log file per shard, not one global log file).

---

## 15. Wedge state and read-only fallback

If Stratum detects an invariant violation that it can't safely repair at runtime, it transitions to **wedged**: every subsequent write fails with `STM_EWEDGED`; reads continue. The marker is persisted; remount sees it.

### When this fires

- AEAD MAC mismatch on a write-after-encrypt path.
- Allocator invariant violation (`free_gen < committed_gen` etc.).
- Detected double-free or use-after-free on a paddr.
- Metadata Merkle binding mismatch during a write.

### What your OS should do

- **Surface it loudly.** A wedged fs is a "stop everything and call support" condition.
- **Don't auto-unwedge.** There is no auto-unwedge primitive; it requires operator intervention (`stratum fs verify` + manual review).
- **Have a recovery path.** Read-only mount + dataset-level export to a fresh pool is the canonical recovery for catastrophic wedge. Plan for it in your distro's docs.

### Read-only mount

Stratum can be mounted RO via `stratum fs mount --read-only`. Useful for:

- Forensics / recovery (read the pool without write-side risk).
- Reading a pool from a kernel/initramfs that's "too new" to upgrade the format yet.
- Boot-time tier-zero readiness probes (kernel + initramfs + critical services come up; full RW mount happens after).

---

## 16. SELinux / AppArmor / labeled security

Stratum surfaces xattrs at the POSIX layer, which is enough to carry SELinux contexts (`security.selinux`) and IMA signatures (`security.ima`). The xattr layer's open-addressing-chain integrity is spec-verified ([`reference/18-xattr.md`](reference/18-xattr.md)).

What's NOT shipped:

- **Native labeled-context fields in the inode itself**. SELinux contexts live in xattrs, fetched on each path-walk; performance is acceptable but not optimal.
- **MAC-aware integrity** (the xattr is part of the Merkle chain, but the kernel-side enforcement of "this context cannot be modified after this point" is on the MAC framework, not Stratum).

If your OS uses SELinux-style policy enforcement, Stratum is compatible (xattrs work, persist, and are integrity-protected). If you need higher performance per-inode labeling, that's a feature request.

---

## 17. The Slate UI integration layer

Stratum ships [`slate`](SLATE-DESIGN.md), a Plan-9-shaped TUI daemon. Slate is itself a synthetic 9P filesystem — clients interact with it by reading/writing files in a virtual tree.

### What slate gives you

- A FAR-Commander dual-pane file manager (`stratum tui` is the bundled renderer).
- A programmable surface: scripts, AI agents, alternative renderers (graphical via Halcyon, textual via Utopia) all dial slate's socket and see the same state.
- Per-pane editor, snapshot graph, integrity dashboard, volume map.

### Why an OS author cares

- **Default file manager**: launching `stratum tui` from the user's shell, or auto-spawning slate at session start and pointing Halcyon/Utopia at its socket, gets you a Plan-9-aesthetic system file manager with zero additional code.
- **Programmable**: a system agent (or a user agent — an LLM assistant, an autorun script) can dial slate's `/connection/attach`, navigate via `/panels/X/cursor` + `/panels/X/action`, read the current pane state, and trigger admin verbs. This is the substrate for AI-driven system administration.
- **Multi-pane editor**: slate's `/editor` subtree is RW (mode 0644) and supports save/quit/revert verbs. Your OS's text-editing surface can be built on slate without a custom editor toolkit.

See [`SLATE-DESIGN.md`](SLATE-DESIGN.md) for the schema contract. The renderer (`stratum tui`) is in `v2/tools/stratum/`; slate itself is in `v2/src/slate/`.

---

## 18. Common pitfalls

In rough order of how often they bite OS integrators:

1. **Embedding the `.key` in the pool header.** Don't. The separability is the second factor. See §5.
2. **Trying to take a snapshot during a high-throughput write loop.** Snapshot create drains the dirty buffer first; expect a brief stall. Schedule when quiescent.
3. **Mocking the filesystem in integration tests.** Mocks diverge from real behavior; use a real Stratum mount for integration tests (the C suite + Rust e2e are the model — see §19).
4. **Disabling SO_PEERCRED checks on `/ctl/` for "convenience."** The `--allow-unauth` flag is for tests; never in production. Admin verbs get exposed to any local user.
5. **Assuming cross-dataset reflink works.** Refused with `STM_EXDEV` at the sync layer; gated on the rekeying primitive. Plan around single-dataset reflink for now.
6. **Holding many fids open from a single 9P client across long-running operations.** libstratum-9p is one-op-at-a-time per connection; for parallelism, open multiple connections (see the unique-fid-base discipline used by slate-tty and the TUI pollers).
7. **Writing snapshot names with embedded newlines.** Refused server-side; refuse client-side too with a clear error.
8. **Forgetting `mlock(2)` on the unwrapped key.** Hibernation file leaks the key. Always `mlock` + `MADV_DONTDUMP`.
9. **Bumping `msize` without bumping `iounit` accounting.** The protocol allows up to msize-headers; if your client lib doesn't chunk correctly, you'll get truncated writes.
10. **Skipping the audit cycle on filesystem-invariant changes.** The R-series (R0..R136 closed, growing) catches regressions that the test suite misses. If you contribute to Stratum upstream, the [CLAUDE.md trigger list](../../CLAUDE.md) tells you which surfaces need an audit.

---

## 19. Testing your integration

### What ships

- **C suite**: 54 ctest binaries covering every subsystem. Run via `ctest --test-dir v2/build -j4`. Baseline: 54/54 GREEN.
- **Rust e2e**: 33-case CRUD harness against a live stratumd over the wire. Run via `cargo test --release` in `v2/tools/stratum-fs-e2e/`.
- **Slate socket smoke**: e2e against a live slate daemon over `--allow-unauth`. Run via `cargo test --release` in `v2/tools/stratum-slate-tty/`.
- **Concurrent /ctl/**: 2-case Rust harness verifying concurrent-accept wall-time bounds. `v2/tools/stratum/tests/concurrent_ctl.rs`.
- **Compound-op race class**: 9-case pthread harness in `v2/tests/test_compound_ops_concurrent.c`. Each case proves a specific lock-order or atomicity invariant.

### For your OS

- **xfstests harness**: planned (POLISH-2; #928). When it lands, run against your kernel-v9fs mount.
- **Boot-loop test**: take a snapshot, intentionally break userspace, reboot, verify rollback. This is your distribution's most valuable integration test.
- **Pull-the-plug test**: kill stratumd with SIGKILL mid-write. Verify mount succeeds and state is consistent post-recovery. This is the crash-safety regression that any production-grade OS needs.
- **Tier-migration test**: write enough data to push a dataset over the demote threshold, trigger `migrate-policy-step`, verify reads still serve correctly from the demoted tier.

### Performance baselines

POLISH-3 (#929) covers the perf baseline against ext4/btrfs/ZFS on a real Linux disk. Until that lands, run your own fio harness against the v9fs mount. Expect: write throughput comparable to ZFS-on-Linux with similar compression settings; metadata ops slightly faster than btrfs (Bε-tree lookup); first-read AEAD verification adds ~3-5% overhead vs unencrypted btrfs.

---

## 20. What's not done yet (the honest list)

Roadmap chunks that an OS author should plan around:

- **io_uring-native write path** — v2.x mid-cycle.
- **Content-defined extent boundaries** (novel angle #3) — v2.x mid-cycle.
- **Kernel-native Stratum module** — long-term; v9fs-over-stratumd is the today path.
- **Learned tier policy** (novel angle #6) — v2.x late.
- **Cross-dataset reflink** + **per-dataset rekeying** — architectural; gated on the rekeying primitive.
- **OTLP exposition** — sidecar translator until then; Prometheus is the v2.x baseline.
- **inotify/fanotify event delivery** — needs Stratum 9P extension; v2.x late.
- **Snapshot rollback UI verb** (SWISS-6 v1.1c) — pending; v2.x near-term.
- **Quotas / reservations** — v2.x mid-cycle.
- **Force-replay-from-snapshot recovery verb** — v2.x late.
- **TLC formal-spec verification in CI** — three specs pending TLC verification (tooling-gated); the specs themselves are written.

The roadmap is honest: nothing here is hidden behind a "coming soon" page. The `docs/ROADMAP-V2.md` document tracks priorities; the GitHub-style task list in CLAUDE.md memory tracks the actual chunk-by-chunk plan.

---

## 21. Where to ask questions and contribute

- **Code**: this repository. Read CLAUDE.md for the project's discipline (spec-first, audit-triggering changes, design-decision docs).
- **Specs**: `v2/specs/*.tla` — the formal model. If you're proposing a feature that touches concurrency, commit ordering, nonce uniqueness, quorum, redundancy, crypto key derivation, cache coherence, or torn-write recovery, the spec gets written FIRST.
- **Audits**: when you contribute a change to an audit-triggering surface (see CLAUDE.md's trigger list), spawn the audit round and address P0/P1 findings before merge. The closed-list in `memory/audit_v2_r0_closed_list.md` is the do-not-re-report preamble.

If you're building a distribution on Stratum and run into something the docs don't cover, the answer is usually in one of:

- [`REFERENCE.md`](REFERENCE.md) for "what is the as-built behavior of X?"
- [`ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for "why does Stratum do X this way?"
- [`ROADMAP-V2.md`](../../docs/ROADMAP-V2.md) for "is X planned?"
- The relevant `specs/*.tla` for "is X formally specified?"
- [CLAUDE.md](../../CLAUDE.md) for "what's the audit posture around X?"

When in doubt: read the spec, then the reference, then the code. The spec is the source of truth.

---

## Appendix A: A minimal Linux installer flow

For OS authors writing the install path against Stratum, the rough sequence:

```bash
# 1. Partition the disk.
sgdisk -n 1:0:+512M -t 1:ef00 /dev/sda                  # ESP
sgdisk -n 2:0:0     -t 2:8300 /dev/sda                  # Stratum pool

# 2. Format the pool.
stratum mkfs --pool /dev/sda2 \
             --key  /tmp/wrapped.key \
             --passphrase-fd 3 \
             3< <(echo "user's passphrase")

# 3. Create the root dataset + mount.
stratum serve --pool /dev/sda2 --key /tmp/wrapped.key \
              --fs-listen /tmp/install.sock --daemonize
mount -t 9p -o trans=unix,version=9p2000.L /tmp/install.sock /mnt

# 4. Unpack the OS into /mnt.  (tar / debootstrap / rpm-ostree / whatever.)

# 5. Install the .key sidecar onto the ESP (or wherever your policy says).
cp /tmp/wrapped.key /mnt/boot/efi/stratum.key
chmod 0400 /mnt/boot/efi/stratum.key

# 6. Install the bootloader + initramfs.
#    The initramfs MUST include:
#      - stratum  (the unified binary)
#      - the key-unwrap module (your passphrase / TPM / hardware-token flow)
#      - the mount-9p-on-unix-socket logic from §4
arch-chroot /mnt grub-install /dev/sda
arch-chroot /mnt mkinitcpio -p linux         # or dracut, or whatever

# 7. Take the post-install snapshot.
echo "post-install" > /tmp/install.sock/ctl/datasets/1/create-snapshot

# 8. Unmount + shutdown stratumd cleanly.
umount /mnt
stratum admin --sock /tmp/install.sock shutdown

# 9. Wipe the ephemeral unwrapped-key file.
shred -u /tmp/wrapped.key
```

This is the shape. The actual commands depend on your distro's tooling (whether you wrap stratum in a higher-level installer, whether you generate the initramfs with mkinitcpio or dracut, etc.).

---

## Appendix B: Mapping legacy filesystem concepts to Stratum

For OS authors coming from ZFS / btrfs:

| ZFS / btrfs concept | Stratum equivalent |
|---|---|
| Pool / volume group | Pool (one stratumd per pool) |
| Vdev (mirror, raidz) | Device roster in pool; redundancy model per `specs/quorum.tla` |
| Dataset / subvolume | Dataset (per-dataset DEK, properties, snapshots) |
| `zfs snapshot` | `/ctl/datasets/<id>/create-snapshot` |
| `zfs rollback` | `/ctl/datasets/<id>/rollback-snapshot` (SWISS-6 v1.1c forward-noted) |
| `zfs hold` / `release` | `/ctl/datasets/<id>/{hold,release}-snapshot` |
| `zfs send / recv` | `stratum fs send` / `recv` (carry from v1; v2 surfacing in progress) |
| `zpool scrub` | `/ctl/pools/<uuid>/scrub-trigger start` |
| `zpool status` | `/ctl/pools/<uuid>/status` + `devices/<id>/status` |
| `zfs get / set` | `/ctl/datasets/<id>/properties` + `set-property` |
| `zfs list -t snapshot` | `/ctl/datasets/<id>/snapshots/` directory listing |
| ZIL (intent log) | Not separately exposed; sync writes go through the three-phase commit |
| L2ARC | Not present; Stratum's tier model is per-extent, not cache-as-layer |
| Quotas | Roadmap |
| btrfs `qgroup` | Roadmap |
| btrfs `defrag` | Not needed (COW with periodic scrub-driven coalescing); explicit defrag verb is a forward-note |
| LUKS / dm-crypt | Not needed (Stratum encrypts every extent natively) |

For OS authors coming from ext4 / XFS:

| ext4 / XFS concept | Stratum equivalent |
|---|---|
| `mkfs.ext4` | `stratum mkfs` |
| `tune2fs` | `/ctl/datasets/<id>/set-property` |
| `e2fsck` | No equivalent; crash-safety is by-construction. Refer to `stratum fs verify` for full Merkle-chain re-verify. |
| `xfs_growfs` (online resize) | Roadmap (pool grow + dataset grow as separate verbs) |
| `xfs_io / chattr +i` (immutable) | `F_SEAL_WRITE` via `fcntl(F_ADD_SEALS)` |
| `chattr +A` (no atime) | Per-dataset `atime` property (roadmap) |
| `xfs_quota` | Roadmap |
| Discard / TRIM | Stratum issues TRIM on free at sync-commit boundaries |

---

**Document state**: living document; updates land alongside roadmap chunks that change the integration surface. Last updated alongside the Phase 9.5 PARALLEL-3 impl-5 ship (per-inode lock granularity).

**Audience**: OS authors evaluating or actively integrating Stratum. Not a developer-onboarding doc for Stratum itself — for that, start with `CLAUDE.md`.

**Length**: ~7,500 words. Designed to be read sectional-on-demand; the §3 / §4 / §18 path is the fast path.
