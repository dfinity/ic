use clap::Parser;
use ic_types::ReplicaVersion;
use std::path::PathBuf;
use url::Url;

use crate::{
    app_subnet_recovery::AppSubnetRecoveryArgs,
    nns_recovery_failover_nodes::NNSRecoveryFailoverNodesArgs,
    nns_recovery_same_nodes::NNSRecoverySameNodesArgs,
};

/// Subcommands for recovery procedures (application subnets, NNS with failover nodes, etc...)
#[derive(Parser)]
pub enum SubCommand {
    /// Application subnet recovery on same or failover nodes.
    AppSubnetRecovery(AppSubnetRecoveryArgs),
    /// NNS recovery on a failover IC.
    NNSRecoveryFailoverNodes(NNSRecoveryFailoverNodesArgs),
    /// NNS recovery on the same nodes.
    NNSRecoverySameNodes(NNSRecoverySameNodesArgs),
}

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct RecoveryToolArgs {
    #[clap(
        short = 'r',
        long,
        alias = "registry-url",
        default_value = "https://ic0.app"
    )]
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
