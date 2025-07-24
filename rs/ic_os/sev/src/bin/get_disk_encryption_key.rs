use anyhow::{Context, Result};
use clap::Parser;
use ic_sev::guest::key_deriver::{Partition, SevKeyDeriver};

#[derive(Parser)]
struct Args {
    /// The partition to get encryption key for
    #[arg(value_enum, long)]
    partition: Partition,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut provider = SevKeyDeriver::new()?;
    print!(
        "{}",
        provider
            .derive_key(args.partition)
            .context("Could not get disk encryption key")?
    );
    Ok(())
}
