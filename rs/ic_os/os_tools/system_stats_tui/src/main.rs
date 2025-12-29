use std::time::Duration;

use clap::Parser;
use system_stats_tui::app::App;

fn parse_duration(arg: &str) -> Result<Duration, String> {
    Ok(
        match duration_string::DurationString::try_from(String::from(arg)) {
            Ok(val) => val.into(),
            Err(duration_string::Error::Format) => return Err("invalid format".to_string()),
            Err(duration_string::Error::Overflow) => return Err("duration too large".to_string()),
            Err(duration_string::Error::ParseInt(e)) => return Err(format!("invalid number: {e}")),
        },
    )
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Base URL with IPv4 / IPv6 address or hostname of the machine to analyze.
    #[arg(short, long, default_value = "http://localhost")]
    address: String,

    /// How frequently to sample the exporters on the machine.
    #[arg(short, long, value_parser = parse_duration, default_value= "5s")]
    sampling_frequency: Duration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let terminal = ratatui::init();
    let result = App::new(args.address, args.sampling_frequency)
        .run(terminal)
        .await;
    ratatui::restore();
    result
}

