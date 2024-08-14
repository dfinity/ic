use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum Commands {
    /// Check for unused component files
    CheckUnusedComponents,
}

#[derive(Parser)]
#[command()]
struct ManifestArgs {
    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ERROR: this only runs on Linux.");
        std::process::exit(1);
    }
    let opts = ManifestArgs::parse();

    match opts.command {
        Some(Commands::CheckUnusedComponents) => {
            println!("CheckUnusedComponents command was invoked");
            Ok(())
        }
        None => Ok(()),
    }
}
