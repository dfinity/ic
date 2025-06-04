use clap::Parser;
use ic_cup_explorer::{explore, verify};
use ic_types::SubnetId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

/// Subcommands for handling CUPs
#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
enum SubCommand {
    /// Explore and optionally download the latest CUP of a subnet
    Explore(ExploreArgs),
    /// Verify a given CUP
    Verify(VerifyArgs),
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
struct ExploreArgs {
    /// Id of the subnet
    #[clap(long, value_parser=ic_cup_explorer::util::subnet_id_from_str)]
    subnet_id: SubnetId,

    /// The directory to download the latest CUP to
    #[clap(long)]
    download_path: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
struct VerifyArgs {
    /// The location of the CUP
    #[clap(long)]
    cup_path: PathBuf,

    /// The NNS public key PEM file to be used to verify registry replies
    #[clap(long)]
    nns_pem: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
struct CupExplorerArgs {
    #[clap(
        short = 'r',
        long,
        alias = "registry-url",
        default_value = "https://ic0.app"
    )]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_url: Url,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[tokio::main]
async fn main() {
    let args = CupExplorerArgs::parse();

    match &args.subcmd {
        SubCommand::Explore(explore_args) => {
            explore(
                args.nns_url,
                explore_args.subnet_id,
                explore_args.download_path.clone(),
            )
            .await;
        }
        SubCommand::Verify(verify_args) => verify(
            args.nns_url,
            verify_args.nns_pem.clone(),
            &verify_args.cup_path,
        ),
    }
}
