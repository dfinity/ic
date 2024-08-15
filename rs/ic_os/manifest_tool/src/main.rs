use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod check_unused_components;
mod components_parser;

#[derive(Subcommand)]
pub enum Commands {
    /// Check for unused component files
    CheckUnusedComponents,
}

#[derive(Parser)]
#[command()]
struct ManifestArgs {
    /// The root of the repository
    #[arg(short, long)]
    repo_root: PathBuf,

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
            check_unused_components::check_unused_components(&opts.repo_root)
        }
        None => Ok(()),
    }
}
