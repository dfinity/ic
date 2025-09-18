use std::fs::File;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::Parser;
use tar::Builder;

use dflate::{add_file_to_archive, scan_file_for_holes};

/// Create deterministic tar archives quickly.
#[derive(Parser)]
struct Args {
    /// Files to archive, can be specified more than once
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    /// Archive path
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut dest = Builder::new(File::create(args.output)?);

    for file in args.input {
        let mut source = File::open(&file)?;
        let file_name = file
            .file_name()
            .ok_or(anyhow!("Invalid path: '{}'", &file.display()))?
            .to_string_lossy()
            .into_owned();

        let state = scan_file_for_holes(&mut source, file_name)?;
        add_file_to_archive(&mut source, &mut dest, state)?;
    }

    // Dropping the `Builder` will add the required end-of-archive entry
    Ok(())
}
