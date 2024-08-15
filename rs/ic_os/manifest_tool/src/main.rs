use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod components_parser;
use components_parser::get_icos_manifest;

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
            let icos_components = get_icos_manifest(&opts.repo_root)?;
            dbg!(icos_components);
            dbg!(opts.repo_root);
            Ok(())
        }
        None => Ok(()),
    }
}
