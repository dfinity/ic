use anyhow::Result;
use clap::{Parser, Subcommand};

mod components_parser;
use components_parser::get_icos_components;

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
            println!("Current working directory: {:?}", std::env::current_dir()?);

            let icos_components = get_icos_components()?;
            dbg!(icos_components);
            Ok(())
        }
        None => Ok(()),
    }
}
