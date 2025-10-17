use clap::Parser;
use ic_types::ReplicaVersion;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

use crate::{
    app_subnet_recovery::AppSubnetRecoveryArgs,
    nns_recovery_failover_nodes::NNSRecoveryFailoverNodesArgs,
    nns_recovery_same_nodes::NNSRecoverySameNodesArgs,
};

/// Subcommands for recovery procedures (application subnets, NNS with failover nodes, etc...)
#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
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
    #[clap(long)]
    pub replica_version: Option<ReplicaVersion>,

    /// The directory to perform recovery in
    #[clap(long, default_value = "/var/lib/ic/data")]
    pub dir: PathBuf,

    /// The path to a private key to be considered for admin SSH connections
    #[clap(long)]
    pub admin_key_file: Option<PathBuf>,

    /// Flag to enter test mode
    #[clap(long)]
    pub test_mode: bool,

    /// Flag to make the tool non interactive. No input from the user is requested.
    #[clap(long)]
    pub skip_prompts: bool,

    /// Flag to indicate we're running recovery directly on a node, and should use
    /// the locally available binaries. If this option is not set, missing binaries
    /// will be downloaded.
    #[clap(long)]
    pub use_local_binaries: bool,

    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,
}
