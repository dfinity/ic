use clap::Parser;

use std::path::PathBuf;

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct BackupArgs {
    /// Path to the config file
    #[clap(long)]
    pub config_file: PathBuf,
}
