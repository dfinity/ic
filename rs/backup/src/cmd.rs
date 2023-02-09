use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub struct BackupArgs {
    /// Path to the config file
    #[clap(long)]
    pub config_file: PathBuf,

    /// Increase the log verbosity level to DEBUG
    #[clap(long)]
    pub debug: bool,

    /// Command to execute if given, default is to do backup
    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,
}

#[derive(Clone, Parser)]
pub enum SubCommand {
    /// Run the backup process (default command, can be omitted)
    Backup,
    /// Initialize the backup config file
    Init,
    /// Upgrade the backup config file
    Upgrade,
}
