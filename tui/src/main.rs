mod app;
mod cli;
mod config;
mod editor;
mod hostfs;
mod p9;
mod panel;
mod ui;

use anyhow::Result;
use app::App;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::io::stdout;
use std::time::Duration;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // CLI mode: stratum-tui cli <volume> <command> [args...]
    if args.len() >= 2 && args[1] == "cli" {
        return cli::run(&args[2..]);
    }

    let mut app = App::new();
    app.init_host_panel();

    if args.len() > 1 {
        let vol = &args[1];
        let pass = args.get(2).map(|s| s.as_str());
        app.try_open_volume_from_cli(vol, pass);
    }

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Execute deferred blocking actions AFTER the draw
        if app.pending_action.is_some() {
            app.run_pending_action();
            continue;
        }

        // Snapshot dialog — all keys go there
        if app.snap_dialog.is_some() {
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.snap_key(key);
                    }
                }
            }
            continue;
        }

        // MkVolume dialog — all keys go there
        if app.mkvol_dialog.is_some() {
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.mkvol_key(key);
                    }
                }
            }
            continue;
        }

        // Confirm dialog — Y/N modal, takes priority over everything below
        if app.confirm_dialog.is_some() {
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.confirm_key(key);
                    }
                }
            }
            continue;
        }

        // Conflict dialog (during copy) — modal; copy_tick is paused.
        if app.conflict_dialog.is_some() {
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.conflict_key(key);
                    }
                }
            }
            continue;
        }

        // Editor mode — all keys go to editor
        if app.editor.is_some() {
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        if let Some(ref mut ed) = app.editor {
                            ed.handle_key(key);
                        }
                    }
                }
            }
            app.editor_tick();
            continue;
        }

        // Copy mode
        if app.copy_state.is_some() {
            app.copy_tick();
            if event::poll(Duration::from_millis(5))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc {
                        app.cancel_copy();
                    }
                }
            }
            continue;
        }

        // Normal mode
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }

        if app.quit {
            break;
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
