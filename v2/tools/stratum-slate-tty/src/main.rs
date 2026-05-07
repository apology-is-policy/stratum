//! stratum-slate-tty — terminal renderer for the slate daemon.
//!
//! Architecture (docs/SLATE-DESIGN.md §5):
//!
//!   Main thread:       state fetch + render + input → /event verbs.
//!   Redraw thread:     blocks on /redraw; signals main when version
//!                      advances. Holds its OWN libstratum-9p
//!                      connection (the lib is one-op-at-a-time per
//!                      connection — see include/stratum/9p_client.h).
//!
//! v1.0 minimum (per project_v2_next_session.md):
//!   - dial slate's Unix socket
//!   - render two panels from /panels/{left,right}/entries
//!   - arrow keys + Enter + Backspace + Tab + Ctrl-Q
//!   - dialog + editor displayed but not interactive
//!
//! Forward-noted for v1.1+: interactive dialog dismissal,
//! /editor/content RW driving, mouse events, panel selection.

use anyhow::{bail, Context, Result};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode,
        KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

mod ffi;
mod slate;
mod ui;

use slate::{read_lines, read_text_trim, SlateClient};
use ui::{PanelView, UiState};

const DEFAULT_SLATE_SOCKET: &str = "/tmp/stratum-slate.sock";

fn main() -> Result<()> {
    let opts = parse_args()?;
    let mut main_client = SlateClient::dial(&opts.slate_sock)
        .with_context(|| format!("dial slate at {}", opts.slate_sock.display()))?;

    // Spawn /redraw thread on its OWN connection.
    let (redraw_tx, redraw_rx): (Sender<u64>, Receiver<u64>) = mpsc::channel();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let redraw_handle = {
        let stop = Arc::clone(&stop_flag);
        let sock = opts.slate_sock.clone();
        thread::Builder::new()
            .name("slate-tty-redraw".into())
            .spawn(move || redraw_loop(sock, redraw_tx, stop))?
    };

    let result = run_ui(&mut main_client, &opts, &redraw_rx);

    // Best-effort shutdown of the redraw thread. Dropping main_client
    // closes its connection; the redraw thread runs against its own
    // connection and is woken by either (a) the slate daemon stopping,
    // or (b) the connection being closed when this process exits.
    // For a clean shutdown we set the stop flag; the redraw loop
    // observes it after each wake and exits.
    stop_flag.store(true, Ordering::SeqCst);
    let _ = redraw_handle; // detach implicitly via drop

    result
}

struct Opts {
    slate_sock: PathBuf,
}

fn parse_args() -> Result<Opts> {
    let mut slate_sock = PathBuf::from(DEFAULT_SLATE_SOCKET);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--slate-sock" | "-s" => {
                let v = args.next().context("--slate-sock requires a value")?;
                slate_sock = PathBuf::from(v);
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                bail!("unknown argument: {other}\n(see --help)");
            }
        }
    }
    Ok(Opts { slate_sock })
}

fn print_usage() {
    println!(
        "Usage: stratum-slate-tty [--slate-sock PATH]\n\n\
         Connects to a running stratum-slate daemon and renders its UI.\n\n\
         Options:\n\
           -s, --slate-sock PATH   Slate Unix-socket path\n\
                                   (default: {DEFAULT_SLATE_SOCKET})\n\
           -h, --help              Show this message\n\n\
         Keys:\n\
           Tab              switch focused panel\n\
           Up / Down        move cursor\n\
           Enter            descend into directory\n\
           Backspace        ascend to parent\n\
           Ctrl-Q / Ctrl-C  quit\n"
    );
}

fn redraw_loop(
    slate_sock: PathBuf,
    tx: Sender<u64>,
    stop: Arc<AtomicBool>,
) {
    let mut client = match SlateClient::dial(&slate_sock) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redraw: dial failed: {e}");
            return;
        }
    };
    let mut last_version: u64 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match client.redraw_once(last_version) {
            Ok(Some(v)) => {
                last_version = v;
                if tx.send(v).is_err() {
                    break; // main hung up
                }
            }
            Ok(None) => break, // daemon stopped
            Err(_) => {
                // Most often: connection closed mid-poll on shutdown.
                // Exit quietly.
                break;
            }
        }
    }
}

fn run_ui(
    client: &mut SlateClient,
    opts: &Opts,
    redraw_rx: &Receiver<u64>,
) -> Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let mut focus: usize = 0;
    let result = (|| -> Result<()> {
        loop {
            let snapshot = fetch_snapshot(client, opts, focus)?;
            terminal.draw(|frame| ui::render(frame, &snapshot))?;
            // Wait for either a key event or a redraw signal.
            loop {
                if event::poll(Duration::from_millis(100))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            match handle_key(client, &mut focus, &snapshot, key)? {
                                Action::Quit => return Ok(()),
                                Action::Refresh => break,
                                Action::Ignore => {}
                            }
                        }
                        Event::Resize(_, _) => break,
                        _ => {}
                    }
                }
                // Drain redraw signals; we coalesce multiple wakes to
                // a single re-render.
                let mut woke = false;
                while let Ok(_) = redraw_rx.try_recv() {
                    woke = true;
                }
                if woke {
                    break;
                }
            }
        }
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).ok();
    terminal.show_cursor().ok();
    result
}

enum Action {
    Quit,
    Refresh,
    Ignore,
}

fn handle_key(
    client: &mut SlateClient,
    focus: &mut usize,
    snap: &UiState,
    key: crossterm::event::KeyEvent,
) -> Result<Action> {
    // Ctrl-Q / Ctrl-C → quit.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c')))
    {
        return Ok(Action::Quit);
    }

    // F10 is FAR Commander's Quit.
    if matches!(key.code, KeyCode::F(10)) {
        return Ok(Action::Quit);
    }

    match key.code {
        KeyCode::Tab => {
            *focus ^= 1;
            return Ok(Action::Refresh);
        }
        KeyCode::Up => action_verb(client, *focus, "key Up\n")?,
        KeyCode::Down => action_verb(client, *focus, "key Down\n")?,
        KeyCode::Enter => action_verb(client, *focus, "key Enter\n")?,
        KeyCode::Backspace => action_verb(client, *focus, "key Backspace\n")?,
        KeyCode::F(n) if n >= 1 && n <= 9 => {
            // Forward F1-F9 to slate as named verbs. Slate v1.0 returns
            // STM_ENOTSUPPORTED for these; future slate chunks will
            // light them up.
            action_verb(client, *focus, &format!("key F{n}\n"))?;
        }
        _ => {
            let _ = snap; // hint about future per-state key handling.
            return Ok(Action::Ignore);
        }
    }
    // Action verbs bump slate's version, which the redraw thread will
    // detect and signal. We DO NOT fetch state inline here — instead
    // we wait for the redraw signal which proves the action took
    // effect (avoids a TOCTOU read where the action hasn't landed).
    Ok(Action::Ignore)
}

fn action_verb(client: &mut SlateClient, focus: usize, verb: &str) -> Result<()> {
    let path = if focus == 0 {
        "/panels/left/action"
    } else {
        "/panels/right/action"
    };
    // STM_ENOTSUPPORTED on unknown verbs is fine — we just ignore it.
    let _ = client.write_path(path, verb.as_bytes());
    Ok(())
}

fn fetch_snapshot(
    client: &mut SlateClient,
    opts: &Opts,
    focus: usize,
) -> Result<UiState> {
    // Per docs/SLATE-DESIGN.md §6: wrap the read in a V0=V1 retry to
    // get a consistent snapshot. We skip the retry here for v1.0 —
    // every read goes through the same daemon mutex; intermediate
    // ops will be picked up on the next redraw signal.
    let version: u64 = read_text_trim(client, "/version")?
        .parse()
        .unwrap_or(0);
    let status = read_text_trim(client, "/status").unwrap_or_default();
    let connected_raw = read_text_trim(client, "/connection/connected").unwrap_or("0".into());
    let connected = connected_raw == "1";
    let backend_socket = read_text_trim(client, "/connection/socket").unwrap_or_default();

    let panel_left = read_panel(client, "/panels/left", connected)?;
    let panel_right = read_panel(client, "/panels/right", connected)?;

    let dialog_stack = read_text_trim(client, "/dialogs/stack").unwrap_or_default();

    let editor_active = read_text_trim(client, "/editor/active")
        .map(|s| s == "1")
        .unwrap_or(false);
    let editor_filename = if editor_active {
        read_text_trim(client, "/editor/filename").unwrap_or_default()
    } else {
        String::new()
    };
    let editor_modified = read_text_trim(client, "/editor/modified")
        .map(|s| s == "1")
        .unwrap_or(false);
    let editor_preview = if editor_active {
        // Don't read the full /editor/content (could be 1 MiB); just
        // show the first ~200 lines for v1.0.
        read_lines(client, "/editor/content")
            .unwrap_or_default()
            .into_iter()
            .take(200)
            .collect()
    } else {
        Vec::new()
    };

    let _ = opts; // socket_path was a header field; v1.0 header drops it.
    Ok(UiState {
        version,
        status,
        connected,
        backend_socket,
        focus,
        panels: [panel_left, panel_right],
        dialog_stack,
        editor_active,
        editor_filename,
        editor_modified,
        editor_preview,
    })
}

fn read_panel(
    client: &mut SlateClient,
    base: &str,
    connected: bool,
) -> Result<PanelView> {
    let path = read_text_trim(client, &format!("{base}/path")).unwrap_or_default();
    let raw_entries = read_lines(client, &format!("{base}/entries")).unwrap_or_default();
    let cursor: u32 = read_text_trim(client, &format!("{base}/cursor"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(PanelView { path, raw_entries, cursor, connected })
}
