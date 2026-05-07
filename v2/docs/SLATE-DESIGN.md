# slate — design

`stratum-slate` is the v2 TUI architected as a Plan 9-style synthetic
filesystem. The daemon owns all UI state; clients (terminal renderer,
scripts, Claude, future Halcyon panes) interact with it purely by
reading and writing files in a 9P tree. The architecture is deliberate:

- **Inspectable.** Any 9P client can `cat` the daemon's view of the
  world and see exactly what the user sees. Bug reports become 9P
  transcripts. Tests become file I/O.
- **Scriptable.** Cron jobs, AI agents, or other apps can drive the
  TUI without simulating a terminal.
- **Multi-frontend.** A terminal renderer is the v1.0 client; a future
  Halcyon graphical pane reads the same contract.
- **One-binary friendly on Mac/Linux.** Casual users still type one
  command and see a TUI.

The name "slate" comes from layered rock (on-theme with Stratum) and
the clean-slate UI metaphor. Pleasingly mundane, like rio.

## 1. Mission

The v1 TUI was a monolith. It worked, but the rendering, business
logic, and state lived in one process; nobody outside that process
could observe or drive it. This is wrong for a Plan 9-shaped project.
slate splits the architecture along the canonical cut: state lives in
a synthetic FS, the renderer is a thin client, and any 9P consumer
becomes a peer.

The contract is the synfs schema. Everything else — number of
binaries, threading model, transport — is implementation detail
that can change without breaking clients.

## 2. Three invocation modes (one binary)

```
stratum-slate                    convenience: spawn child `serve`,
                                 run `tty`, kill child on tty exit.
                                 Mac/Linux casual users.

stratum-slate serve [--listen S] long-lived daemon. Defaults:
                                 /tmp/stratum-slate.sock. Thylacine's
                                 default at boot.

stratum-slate tty SOCKET         terminal renderer attached to a
                                 running daemon at SOCKET.

stratum-slate connect SOCKET     attach a stratumd backend (the FS we
                                 browse). Convenience for scripts;
                                 same effect as `echo stratumd-sock >
                                 /slate/connection/attach`.
```

A daemon without any tty client serves the synfs and waits. A tty
without a daemon errors with "no slate daemon at SOCKET". The no-arg
mode is the v1.0 user-facing default.

## 3. Synfs schema

The slate daemon's root tree. All files are textual, line-oriented.
Numeric values are decimal; status fields use enumerated keywords.

```
/
├── version         (R)  monotonic state-version counter; bumps on every
│                        state change. Clients use this to detect staleness.
├── status          (R)  status-line text (one line, free-form).
├── event           (W)  keystrokes / mouse events. Append-only: write a
│                        single event line; daemon dispatches.
├── redraw          (R)  blocking read; daemon holds the read until version
│                        advances past the caller's last-seen value (passed
│                        as a Tread offset). Returns the new version.
├── focus           (RW) "left" | "right" — which panel has the cursor.
├── connection/
│   ├── socket      (R)  current stratumd socket, or empty if disconnected.
│   ├── connected   (R)  "1" | "0".
│   └── attach      (W)  write a stratumd socket path to (re)connect.
├── panels/
│   ├── left/
│   │   ├── path        (R)  current directory in the panel; "/" at root.
│   │   ├── entries     (R)  one line per visible entry. Format below.
│   │   ├── cursor      (RW) numeric index into entries; write to move.
│   │   ├── selection   (RW) comma-separated indices (multi-select).
│   │   └── action      (W)  fire a handler. Lines below.
│   └── right/...        (same shape)
├── dialogs/
│   ├── stack       (R)  comma-separated active dialog ids ("0,1"); newest
│   │                    last. Empty when no dialogs are up.
│   └── <id>/
│       ├── kind    (R)  "confirm" | "input" | "snapshot-list" |
│       │                "conflict" | "mkvol" | …
│       ├── title   (R)  one line.
│       ├── body    (R)  multi-line.
│       ├── options (R)  comma-separated ("ok,cancel" /
│       │                "skip,overwrite,keepboth" / …).
│       ├── input   (RW) for kind=input: the editable string.
│       └── result  (W)  write one of `options` to dismiss.
├── editor/
│   ├── active      (R)  "1" if an editor is open, else "0".
│   ├── filename    (R)  filename being edited.
│   ├── content     (RW) editor buffer (full text).
│   ├── cursor      (RW) "row,col" 0-indexed.
│   ├── modified    (R)  "1" | "0".
│   └── action      (W)  "save" | "quit" | "revert" | "save-and-quit".
└── log/
    ├── tail        (R)  last 100 status events; newest last.
    └── append      (W)  push a status event (used internally; clients
                         may write to surface diagnostics).
```

### `entries` line format

```
TYPE MODE SIZE MTIME NAME
```

- `TYPE` — single char: `d` (dir), `-` (file), `l` (symlink), `?` (other).
- `MODE` — POSIX permission bits in octal (`0644`).
- `SIZE` — decimal bytes; `-` for entries where size is unmeaningful.
- `MTIME` — Unix epoch seconds; `0` if unknown.
- `NAME` — the entry name. Spaces in names are not escaped at v1.0;
  this is acceptable because filename chars are server-side restricted
  to the safe set (R99 P2-1 line-injection gate). If we ever loosen
  that constraint this format must adopt explicit quoting.

### `action` payload

Each line on `action` is a verb optionally followed by arguments:

```
key F3                fire the F3 handler on this panel
key q                 fire 'q'
key Ctrl-c
mouse 12 3 left       click row 12 col 3, left button
goto /etc             cd to /etc
refresh               re-scan the current dir
```

Verbs are extensible; daemon errors on unknown verbs.

### `event` payload

Same format as `panels/X/action` but with an explicit panel selector
prefix (otherwise targets the focused panel):

```
left key F3
right mouse 5 0 left
focus key q              # global key — addresses focus, not a panel
```

### Dialog example: confirm overwrite

```
$ ls /slate/dialogs/
stack
0
$ cat /slate/dialogs/stack
0
$ cat /slate/dialogs/0/kind
confirm
$ cat /slate/dialogs/0/title
File exists
$ cat /slate/dialogs/0/body
Overwrite /backup/foo.txt?
$ cat /slate/dialogs/0/options
overwrite,skip,keepboth,cancel
$ echo overwrite > /slate/dialogs/0/result
# dialog dismissed; copy resumes; version bumps
```

## 4. Event model

`/event` (or `/panels/X/action`) is the only mutation path for UI
intents. The daemon serialises all events and dispatches them through
the same handler the v1 TUI's `handle_key` would have called. Events
are processed FIFO; clients that want to know the result poll
`/version` or block on `/redraw`.

Mouse and keypress encoding is deliberately textual rather than binary
so any tool can write it: `echo "key F5" > /slate/event` is a copy
trigger.

## 5. Redraw model

Renderers MUST NOT poll `/version` in a tight loop. Instead they issue
a Tread on `/redraw` with offset = last-seen-version. The daemon
holds the read until version > offset, then returns the new version
as a decimal string. This gives wakeup latency ~= 0 and zero idle CPU.

Multiple readers on `/redraw` all wake on every state change.

## 6. State model

Every public-facing mutation bumps `/version` exactly once. This
means a client that reads `/version`, then reads any state file,
then re-reads `/version` is guaranteed: if the two version reads
match, the state is consistent. (The daemon takes a write-lock for
the duration of a mutation; reads within that window see either the
pre- or post-mutation snapshot, not a torn one.)

Clients that need atomic multi-file reads can:
1. Read `/version` → V0
2. Read whatever they want.
3. Read `/version` → V1.
4. If V0 == V1, the read is consistent. Otherwise retry.

This is the same MVCC pattern stratum's metadata uses. Familiar.

## 7. Trust boundaries

slate sits between users and stratumd; it has no on-disk state of its
own. The trust-boundary surface is small but worth pinning:

1. **Backend connection ownership.** `/slate/connection/attach` accepts
   a Unix socket path and dials it as stratumd. Writing arbitrary paths
   here doesn't exfiltrate data (the daemon process can't read what it
   couldn't already read), but a malicious local writer could redirect
   the panel to a different dataset. v1.0 accepts this; v1.1 may add
   per-uid ACL on `attach`.

2. **Event source authentication.** v1.0 accepts events from any 9P
   client connected to the slate socket. The Unix socket is mode 0600
   so only the owning UID can connect. This is enough for desktop
   use; multi-user servers need finer auth (forward-noted).

3. **Dialog `result` injection.** Writing to `/slate/dialogs/0/result`
   dismisses a dialog. If a malicious client races a real user's
   confirm, it could click "overwrite" without the user's consent.
   Mitigation v1.0: only the most-recent dialog (top of stack) accepts
   results; earlier ones are read-only. v1.1 may add a nonce in the
   dialog id that scripts must echo back.

## 8. Phasing

```
P9-SLATE-0   design doc + invocation-mode skeleton (this commit).

P9-SLATE-1   daemon scaffold: 9P listener, /version, /status,
             /event, /redraw blocking-read. No real UI yet — write
             to /event prints "got: …" on /log/tail.

P9-SLATE-2   /connection/attach + libstratum-9p plumbing.
             /panels/left/path + /entries (read-only).

P9-SLATE-3   panel cursor + selection + action ("key F3" cat-style
             read; "key Enter" descend dir).

P9-SLATE-4   dialogs (confirm + input). [SLATE-4-confirm shipped:
             single-dialog stack with confirm kind. SLATE-4b shipped:
             multi-dialog stack (N=4) + input kind + dialog_consume()
             API for dismiss-pickup. /dialogs/<id>/input is RW;
             DialogStackLIFO enforced — only top of stack accepts
             results. Single-record completion store; v1.1 may add
             per-id queue.]

P9-SLATE-5   editor/. [SLATE-5a shipped: scaffold + /event "editor open
             <path>" / "editor close" verbs; /editor/{active,filename,
             content,cursor,modified} read-only at v5a; backend Twalk +
             Tlopen + Tread loop reads file into 1 MiB-bounded heap
             buffer; /editor/action returns STM_ENOTSUPPORTED. SLATE-5b
             will lift content + cursor to RW + add save/quit/revert/
             save-and-quit action verbs.]

P9-SLATE-6   stratum-slate-tty: terminal renderer. Reads /redraw,
             /panels/*, /dialogs/*; writes /event. Lifts ratatui
             draw calls from v1's ui.rs.

P9-SLATE-7   admin views (/snapshots, /pools, /scrub, /events) —
             gated on P9-CTL-2 (/ctl/-on-stratumd).

P9-SLATE-8   no-arg invocation mode (spawn child + run tty +
             cleanup). Mac/Linux UX polish.
```

P9-TUI-2a (the lifted v1 monolith) stays in tree as
`v2/tui/` until slate reaches feature parity, then archived as
`v2/tui-monolith/` for reference.

## 9. Forward-notes for Halcyon

Halcyon is Thylacine's graphical shell (graphical, full output —
video, GPU). slate's synfs is data-only — it does not assume a
terminal. A Halcyon "slate-pane" widget would:

- Read `/slate/version` to track when to redraw.
- Read `/slate/panels/left/entries` and render with custom typography.
- Translate mouse + keyboard into `/slate/event` writes.
- Compose with other Halcyon panes naturally; slate doesn't compete
  for the screen.

The schema must therefore stay agnostic about cursor cells, color
codes, and bounding boxes. Renderers translate logical model to
their medium.

## 10. Forward-notes for v1.1+

- **Multi-pane layouts beyond left/right** (tile / stack / tabs):
  /panels/<id>/ instead of /panels/{left,right}/. Schema-extensible
  without breaking v1.0.
- **History / undo**: /undo/{push,pop} as event verbs, /history as
  read-only log.
- **Search**: `/find/query` (W) + `/find/results` (R).
- **Theming**: not in slate's contract; renderers own it.
- **Multi-user sessions**: Unix-socket SO_PEERCRED gate; nonces on
  dialog results. Forward-noted.

## 11. SPEC-TO-CODE mapping

When P9-SLATE-1 lands, `v2/specs/slate.tla` will model the version-
bump invariant, the dialog stack, and the event-FIFO ordering.
v1.0 of the spec is small (~100 lines TLA+) but pins the invariants
that matter:

- `VersionMonotonic` — /version only ever advances.
- `DialogStackLIFO` — only the top dialog accepts results.
- `EventFIFO` — events processed in arrival order.
- `ReadConsistent` — the V0=V1 retry pattern is sound.

## 12. Swiss-army monolith — `stratum` as a portable single binary

Stratum's deployment shape converges on a single statically-linked
binary, `stratum`, that bundles every cmd-line tool and the slate
TUI into one executable. macOS and Linux are the targets.
Veracrypt-shaped UX: drop the binary on any machine, double-click,
browse + manage your stratum volumes — no shared libraries, no
service installs, no PATH wiring.

This is the deployment shape the v1 monolith already had (it could
mount host FS via 9P wrapper, create encrypted .stm volume files,
copy in/out, manage snapshots). Stratum v2 vastly extends what one
binary can do — every subsystem we built since v1 (snapshots,
scrub, integrity verify, send/recv, key rotation, debug
introspection) is reachable from inside the same chrome.

Critically, the synfs contract (slate's 9P tree) stays as the IPC.
Even when stratumd + slate run as threads inside the same process,
slate's tree is still the source of truth. Halcyon (Thylacine's
graphical shell) and any external 9P consumer can subscribe to it
without changing — they connect to the same Unix socket the
embedded slate exposes.

### 12.1 Binary surface

```
stratum                     no-arg landing screen (Veracrypt-shaped)
stratum tui [--vol PATH]    interactive TUI (auto-spawns daemons
                            in-process if --vol is given; otherwise
                            connects to a running slate)
stratum serve VOLUME        run as stratumd (long-lived FS daemon)
stratum slate               run as slate (long-lived UI-state daemon)
stratum mkfs IMAGE          create a new .stm volume
stratum fs CMD ARGS         9P client CLI (ls, stat, read, write, ...)
stratum send / recv         volume snapshot stream (forward-noted)
stratum scrub VOLUME        one-shot integrity scan (forward-noted)
stratum verify VOLUME       Merkle-chain verify (forward-noted)
stratum keyrotate ...       PQ-hybrid key rotation (forward-noted)
```

Subcommands `serve`, `slate`, `mkfs`, `fs` are direct ports of today's
standalone C binaries — same flags, same semantics, same exit codes.
A user with shell muscle memory for `stratumd /tmp/x.stm --listen ...`
types `stratum serve /tmp/x.stm --listen ...` instead.

### 12.2 Embedded-mode `tui`

The default no-fuss workflow is:

```
stratum mkfs /tmp/demo.stm --size 64M
stratum tui --vol /tmp/demo.stm
```

`stratum tui --vol PATH` does not require the user to start daemons.
Internally it:

1. Opens the volume's keyfile (default `<PATH>.key`).
2. Spawns `stm_stratumd_run_main(...)` on a JOINABLE pthread bound
   to a per-process Unix socket (e.g., `$XDG_RUNTIME_DIR/stratum/<pid>/stratumd.sock`).
3. Spawns `stm_slate_run_main(...)` on a second pthread bound to a
   per-process slate socket.
4. Dials slate, writes the stratumd socket path to `/connection/attach`.
5. Runs the renderer in the foreground.
6. On TUI exit, sets stop flags + joins both daemon pthreads cleanly
   (R114 P2-1 doctrine carry — daemons drain their own worker pools).

The slate socket is exposed at a discoverable path so external 9P
clients (Halcyon, scripts, Claude) can attach concurrently — the
embedded mode does NOT lock the user out of the synfs.

### 12.3 Landing screen (no-arg invocation)

`stratum` (no subcommand) shows a Veracrypt-shaped chooser:

```
              ╔═══════════════════════════════════════════╗
              ║              Stratum v2.0                 ║
              ║   PQ-encrypted COW filesystem, portable   ║
              ╠═══════════════════════════════════════════╣
              ║                                           ║
              ║  [O] Open volume...                       ║
              ║  [N] New volume...                        ║
              ║  [H] Browse host filesystem               ║
              ║                                           ║
              ║  Recent volumes:                          ║
              ║    ~/work/projects.stm                    ║
              ║    /Volumes/External/backup.stm           ║
              ║                                           ║
              ║  [F1] Help    [F10] Quit                  ║
              ╚═══════════════════════════════════════════╝
```

Selecting a volume runs the moral equivalent of `stratum tui --vol PATH`.
"Browse host filesystem" attaches to a host-FS-as-9P shim (see §12.6).
Recent volumes persist in a tiny config file under `~/.config/stratum/`.

### 12.4 Capability matrix

The TUI is organised around panes the user can switch between via
F-keys (FAR-Commander idiom). Every pane reads slate's synfs;
every action writes a slate verb that flows through the same
mu-guarded dispatch. Below: pane → operations.

| Pane | Operations |
|---|---|
| **Volume map** (F2)     | donut of used/free split by tier and dataset; snapshot timeline; integrity bar (last-scrub time + error count); compression / dedup ratio gauges. |
| **Browse** (F3, default) | dual-pane navigate (left/right, focus toggle); host↔stratum copy with progress + conflict resolution; mkdir / mkfile / chmod / chown / xattr edit; view (cat) / edit (modal) / hex-view; hardlink / symlink / reflink (cross-volume reflink when target is also stratum). |
| **Snapshots** (F4)      | list with creation-time + hold-count + send-mark; create (named or auto-tagged); delete; hold / release; rollback (with double-confirm); diff between two snaps; mount snap read-only as ghost-pane. |
| **Integrity** (F5)      | scrub start/stop + live throughput + error count; Merkle-chain verify (full / spot); bad-block report with affected files; format check + UB-version probe; recover-from-torn-write. |
| **Encryption** (F6)     | view key state (gen / slot count); add / remove keyslots; rotate master key (gen N → N+1); lock / unlock with passphrase; show wrap algorithm (PQ vs classical fallback); per-extent AEAD details. |
| **Inspect** (F7, admin) | /debug/allocator-state map; btree shape (per-level); extent map (per-file); per-tier stats; 9P wire trace; audit-log browser. |
| **Metrics** (F8)        | live IOPS / cache-hit / compression / dedup gauges; per-dataset usage donut. |
| **Volume admin** (F9)   | create / open with passphrase / open with keyfile / open with janus-daemon; resize; convert (compression / dedup); send-stream / receive-stream; close. |

`F10` quits. `Tab` / `Shift+Tab` switches focused pane within the
current view. `Esc` returns to volume map (F2).

### 12.5 Visualizations

The six screens below are the "make Stratum legible" set — they
turn novel-angle features (Merkle root, content-defined extents,
three-phase sync, PQ-wrap) into things the user can watch.

1. **Volume map** (F2). Single screen. Donut: used vs free by tier
   (hot / cold) and by dataset. Bar: compression / dedup ratios.
   Snapshot timeline (horizontal): created → now, deletion markers.
   Integrity bar: scrub progress, last-verified time, error count.
   This is the README screenshot.

2. **Snapshot graph** (F4). Tree showing lineage (root → snap A → snap
   B → branch C). Held / send-marked annotations. Hover or focus
   shows that snapshot's stat block. Rollback target is marked.
   Sells "snapshots branch like git."

3. **Extent map per file** (F7 sub-view, opened on a file from F3).
   Strip showing each extent — color-coded for dedup hit / unique /
   cold-tier / encrypted / compressed (each with a glyph). Hover
   shows extent metadata: paddr, write_gen, MAC. Sells **content-
   defined extents** — identical bytes in two files visibly share
   the same color block.

4. **Sync phases live** (F8 sub-view). Three-phase sync (G+1
   reservation → flush at G → G+2 final) as a horizontal three-
   segment progress bar. Last 10 syncs as a strip. Current phase
   pulses. Sells **provable crash-safety** — you watch the protocol
   execute in real time.

5. **Btree shape** (F7 sub-view). Each level horizontally; nodes
   colored by recent-access heat. Cursor highlight: "the inode
   you're inspecting lives in this node." Fanout numbers per level.
   Sells **Bε-tree's lock-free metadata path**.

6. **9P wire trace** (F7 sub-view). Live, scrolling. Every Tversion
   / Tattach / Twalk / Tlopen / Tread / Twrite with timing. The
   synfs is THE story; making the wire visible makes Plan-9 design
   choices feel concrete.

### 12.6 Host FS as 9P shim

For host↔stratum copy in F3, the binary needs to read host paths.
v1 did this via a bespoke 9P wrapper that fronted POSIX paths as a
9P tree. v2 inherits the same idea: a `stratum host-fs <path>` mode
exports a host directory tree as 9P on a per-process socket, and
the TUI attaches a second slate panel to that socket. The host pane
is read-only at v2.0 (paranoid default — the user doesn't want the
TUI accidentally rm-rfing their home directory); writes are forward-
noted.

### 12.7 Architecture: one binary, three deployment modes

```
                  ┌────────────────── stratum (single binary) ───────────────┐
                  │                                                          │
                  │   tui mode (default w/ --vol):                           │
                  │     ┌─────────────┐    ┌──────────────┐    ┌──────────┐  │
                  │     │ pthread:    │◀──▶│ pthread:     │◀──▶│ main:    │  │
                  │     │ stratumd    │    │ slate state  │    │ TUI loop │  │
                  │     │             │    │   (synfs)    │    │          │  │
                  │     └─────────────┘    └──────────────┘    └──────────┘  │
                  │            ▲                  ▲                           │
                  │            │ unix sock        │ unix sock                 │
                  │            │                  │                           │
                  │   external 9P clients (Halcyon, scripts) ─────────────────┼─▶
                  │                                                          │
                  │   serve / slate / mkfs / fs subcommands:                 │
                  │     dispatch to stm_<name>_run_main(argc, argv)          │
                  │     — same code path as standalone daemons               │
                  └──────────────────────────────────────────────────────────┘
```

Three deployment modes the same binary supports:

- **Personal**: `stratum tui --vol foo.stm` — daemons embedded as
  pthreads. Good for desktop / laptop use, single user, single
  volume at a time.
- **Operator**: `stratum serve foo.stm --listen /var/run/stratum.sock` +
  `stratum slate --listen /var/run/slate.sock` + `stratum tui` (or
  Halcyon) — daemons run as separate processes, possibly on
  different hosts. Good for servers, NAS, multi-user.
- **Headless**: `stratum send src.stm | ssh dest stratum recv` —
  one-shot subcommands. No TUI, no slate. Good for backups, CI.

### 12.8 Build approach (SWISS-1 chunk)

1. Refactor each cmd binary's `main()` into a public C entry point
   `stm_<name>_run_main(int argc, char **argv)` with the existing
   `main()` as a thin wrapper. Touched files:
   `v2/src/cmd/stratumd/main.c`, `v2/src/cmd/stratum-slate/main.c`,
   `v2/src/cmd/stratum-mkfs/main.c`, `v2/src/cmd/stratum-fs/main.c`.
2. Expose the entry points in a new header `v2/include/stratum/cmds.h`.
3. New Rust crate `v2/tools/stratum/`. `build.rs` enumerates every
   `.a` file under `v2/build/src/**/lib*.a` and emits link directives.
4. `src/main.rs` dispatches subcommands. For `serve` / `slate` / `mkfs` /
   `fs`, FFI-call the C entry points. For `tui`, run the renderer
   in pure Rust.
5. `src/embed.rs` — auto-spawn mode: pthread-spawn stratumd + slate,
   wait for sockets, dial, attach, run TUI; clean teardown on exit.
6. `src/landing.rs` — Veracrypt-shaped no-arg landing screen.
7. Lift the FAR-Commander chrome from `v2/tools/stratum-slate-tty/`.
8. Verify end-to-end on Mac (Linux deferred to chunk N if it
   regresses on the platform-specific bits — but no portability
   concerns are anticipated).

`v2/tools/stratum-slate-tty/` becomes redundant once `stratum tui`
ships with the same chrome; keep it in tree until SWISS-1 is GREEN,
then archive or delete.

### 12.9 Subsequent chunks

The roadmap re-prioritised after live user testing of SWISS-1..3:
the "swiss-army knife" that the user remembers from v1 (and that
sells Stratum visually) is **dual-pane file management with copy
+ mkfs + edit operations**, NOT visualizations. The
visualizations move to a later phase. v1 parity comes first.

#### SWISS-4 — v1 parity (fat sequence, broken into a/b/c/d/e)

The canonical v1 TUI experience: dual-pane FAR-Commander layout
with host on one side + stratum on the other, drag-drop-style
copy, mkfs wizard, passphrase prompt, native editor.

**SWISS-4a — slate per-panel multi-attach (the unblocker).**
Until SWISS-3a, slate had a single backend pointer. Both panels
showed the same backend. SWISS-4a splits state per-panel:

- `s->panel[i].backend` (replaces single `s->backend`).
- `s->panel[i].socket / connected / socket_len`.
- `s->panel[i].entries_count` (cached at panel-entries materialise;
  used by action verb's cursor clamp — closes user-reported bug #2
  at the slate layer too, defense-in-depth on top of SWISS-3b's
  TUI-side clamp).
- Schema additions:
  ```
  /connection/
    left/  (DIR — alias for top-level back-compat)
      socket  / connected  / attach
    right/ (DIR — new)
      socket  / connected  / attach
  ```
  Top-level `/connection/{socket,connected,attach}` stays as a
  legacy alias for the LEFT panel. slate-tty + TUI both speak
  the new schema.
- New API: `stm_slate_attach_panel(s, panel_idx, sock, len)`,
  `stm_slate_disconnect_panel(s, panel_idx)`.
  Existing `stm_slate_attach` becomes alias for `attach_panel(0)`.
- ".." synthesis (user-reported bug #1): when `panel.path != "/"`,
  the panel-entries materialiser prepends a synthetic
  `d 0755 - 0 ..` line. Both backends benefit uniformly.
- editor_open uses `panel[active_idx].backend` (active is passed
  in the verb: `editor open left|right <path>`).

Estimated 800-1200 LOC of slate.c + schema test updates + 3-4
new socket tests + audit (R128).

**SWISS-4b — Shift+F2 host mount + Enter-on-.stm volume mount.**

Per user clarification 2026-05-07:
- **Shift+F2** mounts host filesystem in the **active** panel.
  TUI shows an input-dialog overlay prompting for host path.
  On Enter: spawn `stratum host-fs PATH --listen <session>/host-N.sock`
  + write socket path to `/connection/<active>/attach`.

- **Enter on yellow `.stm` file** mounts that volume in the
  **inactive** panel. The .stm file lives on the active panel's
  backend (typically host-fs). To open it, TUI must reconstruct
  the **host filesystem path** from the panel's backend kind +
  the panel.path + entry.name. Track the panel's backend kind
  in TUI-local state (not in slate; slate doesn't care about
  "kind"). For host-fs panels, root-path is known (TUI spawned
  it); for stratumd panels, .stm files inside don't make sense
  to mount (forward-noted).

- TUI passes the .stm host path to a spawned `stratum serve`
  subprocess + attaches its socket to the inactive panel via
  `/connection/<inactive>/attach`.

- Passphrase prompt: if `<.stm>.key` doesn't exist (or stratumd
  reports STM_EACCES on attach), TUI prompts via input dialog
  for a passphrase + writes to a temp keyfile + retries the
  spawn with `--keyfile <temp>`. Forward-note: the v1.0 keyfile
  format isn't passphrase-derived; SWISS-4b ships a simple
  KDF wrapper. v1.1 may use a proper PBKDF.

Estimated 800-1500 LOC of TUI input dialog + spawn lifecycle +
TUI's per-panel-backend-kind tracking + audit (R129). Lifts
v1's `draw_input_dialog` from `v2/tui/src/ui.rs:371`.

**SWISS-4c — Mkfs wizard (Shift+F7 = MkVol).**

Lifts v1's `draw_mkvol_dialog` from `v2/tui/src/ui.rs:705`. A
multi-field dialog (Name, Size with K/M/G, Encryption on/off,
Passphrase, Compression algo lz4/zstd/none) + OK/Cancel buttons.
On OK, TUI spawns `stratum mkfs PATH --size SIZE [--keyfile ...]`
as a subprocess + waits for completion. Populates the active
panel's cwd (or the user's chosen target path) with the new
.stm file.

Compression / encryption settings need new mkfs flags (forward-
noted to a small mkfs CLI extension). Passphrase derives a
keyfile via the SWISS-4b KDF wrapper.

Estimated 600-1000 LOC of TUI multi-field dialog + mkfs CLI
extension + audit (R130).

**SWISS-4d — Copy operation (F5).**

The headline feature. Lifts v1's `draw_copy_dialog` from
`v2/tui/src/ui.rs:405` (filename + progress bar + throughput
sparkline + ETA — the visual that sells the "watch your bytes
move" experience).

Selection-aware: if the active panel has selected files (via
/panels/X/selection bitset, already in slate), F5 copies them
all. Otherwise copies just the cursor entry.

Conflict resolution: if any destination file already exists,
shows v1's `draw_conflict_dialog` (Skip / Overwrite / KeepBoth +
Apply-to-all-remaining) — lift from `v2/tui/src/ui.rs:865`.

Routes:
- **host → stm**: Tread from host-fs (active panel's backend) +
  Twrite to stratumd (inactive panel's backend).
- **stm → host**: requires host-fs WRITE support — forward-noted
  to a SWISS-4d-host-rw sub-chunk; v1.0 of SWISS-4d ships
  read-from-host + write-to-stratum only.
- **host → host** + **stm → stm**: same shape, different
  backend pointers.

Each in-flight chunk reports throughput to the dialog
(samples ringbuffer); chart renders last 60 samples as the
v2/tui sparkline. ESC cancels (best-effort SIGTERM the
in-flight Twrite + leave partials in place; same as v1).

Estimated 1500-2500 LOC of TUI + audit (R131). The biggest
single SWISS-4 sub-chunk.

**SWISS-4e — Editor wiring (Enter on regular file / F4).**

Slate already has /editor (open / content RW / save / quit /
revert / save-and-quit verbs from SLATE-5b). TUI routes:
- Enter on a non-yellow regular file → `/event "editor open <path>"`.
- F4 → same.
- Inside editor: arrow-key cursor navigation writes /editor/cursor;
  printable chars + Backspace + Enter mutate /editor/content;
  Ctrl-S → /editor/action save; Ctrl-Q → save-and-quit (with
  confirm dialog if modified).

The editor is full-screen (already drawn by SLATE-6's
`draw_editor_overlay`); SWISS-4e wires interactive editing on
top of the existing read-only view.

Estimated 600-1000 LOC of TUI editor input handling + audit
(R132).

#### Visualizations (re-prioritised, post-v1-parity)

After SWISS-4 the binary has dual-pane file ops parity with v1
+ better encryption + Plan-9 IPC. Then visualizations land:

- **SWISS-5**: Volume map (F2) — donut + snapshot timeline +
  integrity bar.
- **SWISS-6**: Snapshot graph (F4 alternate-binding while no
  edit; or move snapshots to F9). Tree of snapshots, hold marks.
- **SWISS-7**: Integrity pane (F5 alternate; or move to F11) —
  scrub progress + Merkle verify.
- **SWISS-8**: Encryption pane — keyslots + rotation.
- **SWISS-9**: Inspect (F7) — /debug/ subtree (allocator,
  btree, extent map).
- **SWISS-10**: Metrics gauges (F8) — Prometheus consumer.

Each chunk: schema design + slate-side surface (if needed) +
Rust visualization + e2e test + audit. Per user policy
2026-05-07, no formal model for slate-side work.

### 12.10 Naming and branding

The single binary is `stratum`. The umbrella library that already
aggregates everything (`add_library(stratum INTERFACE)` in
`v2/CMakeLists.txt`) gives the binary its name. The user-facing
brand: "Stratum is the filesystem you can see — every COW, every
snapshot, every byte of ciphertext, every Merkle root, made
legible." The visualizations (§12.5) are the proof.
