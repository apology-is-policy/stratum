mod app;
mod p9;
mod panel;
mod ui;

use anyhow::Result;
use app::App;
use crossterm::{
    event::{self, Event, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::io::stdout;
use std::time::Duration;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut app = App::new();

    // auto-connect panels from CLI args
    // Usage: stratum-tui [left-addr] [right-addr]
    // Addr format: unix:/path/to/socket  or  host:port
    if args.len() > 1 {
        let addr = &args[1];
        let res = if addr.starts_with("unix:") {
            app.left.connect_unix(&addr[5..])
        } else {
            app.left.connect_tcp(addr)
        };
        match res {
            Ok(()) => app.status = format!("Left connected to {addr}"),
            Err(e) => app.status = format!("Left connect error: {e}"),
        }
    }
    if args.len() > 2 {
        let addr = &args[2];
        let res = if addr.starts_with("unix:") {
            app.right.connect_unix(&addr[5..])
        } else {
            app.right.connect_tcp(addr)
        };
        match res {
            Ok(()) => app.status = format!("Right connected to {addr}"),
            Err(e) => app.status = format!("Right connect error: {e}"),
        }
    }

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(Duration::from_millis(100))? {
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
