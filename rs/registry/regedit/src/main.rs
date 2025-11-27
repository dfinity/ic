//! The main function of ic-regedit processes command line arguments.

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = ic_regedit::args::CliArgs::parse().validate()?;
    let out = ic_regedit::execute_command(cmd)?;
    let out = serde_json::to_string_pretty(&out).expect("Could not pretty print value.");
    println!("{out}");
    Ok(())
}
