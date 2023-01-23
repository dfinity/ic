use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub struct BackupArgs {
    /// Path to the config file
    #[clap(long)]
    pub config_file: PathBuf,

    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,
}

#[derive(Clone, Parser)]
pub enum SubCommand {
    Backup,
    Init,
    Upgrade,
}
