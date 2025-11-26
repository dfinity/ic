use clap::Parser;
use ic_types::{PrincipalId, SubnetId};
use std::path::PathBuf;

#[derive(Clone)]
pub struct ClapSubnetId(pub SubnetId);

impl std::str::FromStr for ClapSubnetId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrincipalId::from_str(s)
            .map_err(|e| format!("Unable to parse subnet_id {e:?}"))
            .map(SubnetId::from)
            .map(ClapSubnetId)
    }
}

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

#[derive(Parser)]
pub enum SubCommand {
    /// Run the backup process (default command, can be omitted)
    Backup,
    /// Initialize the backup config file
    Init,
    /// Upgrade the backup config file
    Upgrade,
    /// Get current replica version of a subnet
    GetReplicaVersion {
        /// The ID of the target subnet
        subnet_id: ClapSubnetId,
    },
}
