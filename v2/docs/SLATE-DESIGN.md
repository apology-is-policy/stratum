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

P9-SLATE-4   dialogs (confirm + input).

P9-SLATE-5   editor/.

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
