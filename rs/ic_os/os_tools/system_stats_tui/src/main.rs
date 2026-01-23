use std::io::stdout;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{Clear, ClearType};
use system_stats_tui::app::App;

fn parse_duration(arg: &str) -> Result<Duration, String> {
    match duration_string::DurationString::from_str(arg) {
        Ok(val) => Ok(val.into()),
        Err(duration_string::Error::Format) => Err("invalid format".to_string()),
        Err(duration_string::Error::Overflow) => Err("duration too large".to_string()),
        Err(duration_string::Error::ParseInt(e)) => Err(format!("invalid number: {e}")),
    }
}

/// System stats TUI for monitoring nodes.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base URL with IPv4 / IPv6 address or hostname of the machine to analyze.
    #[arg(short, long, default_value = "https://localhost")]
    address: String,

    /// How frequently to sample the exporters on the machine.
    #[arg(short, long, value_parser = parse_duration, default_value= "5s")]
    sampling_frequency: Duration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut terminal = ratatui::init();
    // Clear the terminal after init to ensure a clean screen
    terminal.clear()?;
    let result = App::new(args.address, args.sampling_frequency)
        .run(terminal)
        .await;
    ratatui::restore();
    // Clear the terminal after restore to remove any leftover TUI content
    let _ = execute!(stdout(), Clear(ClearType::All));
    result
}
