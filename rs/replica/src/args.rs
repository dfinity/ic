use clap::Parser;
use ic_config::ConfigSource;
use ic_types::ReplicaVersion;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(
    name = "replica",
    about = "Arguments for the Internet Computer Replica.",
    version
)]
pub struct ReplicaArgs {
    /// Print a sample config if set
    #[clap(long)]
    pub print_sample_config: bool,

    /// The path to the Replica config file
    #[clap(long)]
    pub config_file: Option<PathBuf>,

    /// A string representation of the Replica config
    #[clap(long)]
    pub config_literal: Option<String>,

    /// A path to a CBOR-encoded catch-up package to seed the Replica with
    #[clap(long)]
    pub catch_up_package: Option<PathBuf>,

    /// The version of the Replica being run
    #[clap(long)]
    pub replica_version: ReplicaVersion,

    /// Force to use the given subnet ID. This is needed to upgrade NNS
    /// replicas. In that case, we already know which subnet ID we should be
    /// booting with, and trying to determine it from the registry will fail
    /// Example SubnetID: ak2jc-de3ae-aaaaa-aaaap-yai
    #[clap(long)]
    pub force_subnet: Option<String>,

    /// Run the replica in passive state-sync-only mode. The node will join the
    /// subnet's QUIC mesh as an "AI node peer" (must have a matching
    /// `AiNodeRecord` in the registry), download state checkpoints, but will
    /// NOT participate in consensus, message routing, execution, or serve any
    /// public HTTP/XNet endpoints. Used by AI nodes that mirror a subnet's
    /// state for local LLM workloads.
    #[clap(long)]
    pub state_sync_only: bool,
}

impl From<&ReplicaArgs> for ConfigSource {
    fn from(args: &ReplicaArgs) -> ConfigSource {
        if let Some(path) = &args.config_file {
            ConfigSource::File(path.clone())
        } else if let Some(literal) = &args.config_literal {
            ConfigSource::Literal(literal.clone())
        } else {
            ConfigSource::Default
        }
    }
}
