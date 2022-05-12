use clap::Parser;
use ic_types::ReplicaVersion;
use std::path::PathBuf;
use url::Url;

use crate::app_subnet_recovery::AppSubnetRecoveryArgs;

/// Subcommands for recovery procedures (application subnets, NNS with failover nodes, etc...)
#[derive(Parser)]
pub enum SubCommand {
    AppSubnetRecovery(AppSubnetRecoveryArgs),
}

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct RecoveryToolArgs {
    #[clap(short = 'r', long, alias = "registry-url")]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    pub nns_url: Url,

    /// replica version of ic-admin binary
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub replica_version: Option<ReplicaVersion>,

    /// The directory to perform recovery in
    #[clap(long, parse(from_os_str))]
    pub dir: PathBuf,

    /// The path to a private key to be considered for SSH connections
    #[clap(long, parse(from_os_str))]
    pub key_file: Option<PathBuf>,

    /// Flag to enter test mode
    #[clap(long)]
    pub test: bool,

    #[clap(subcommand)]
    pub subcmd: SubCommand,
}
