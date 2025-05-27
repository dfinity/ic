use clap::Parser;
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_cup_explorer::registry::{get_nodes, RegistryCanisterClient};
use ic_cup_explorer::util::{http_url, make_logger};
use ic_cup_explorer::{get_cup, get_subnet_id};
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::types::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::consensus::{CatchUpContentProtobufBytes, CatchUpPackage};
use ic_types::crypto::{CombinedThresholdSig, CombinedThresholdSigOf};
use ic_types::SubnetId;
use prost::Message;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, task};

/// Subcommands for handling CUPs
#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
pub enum SubCommand {
    /// Explore and optionally download the latest CUP of a subnet
    Explore(ExploreArgs),
    /// Verify a given CUP
    Verify(VerifyArgs),
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct ExploreArgs {
    /// Id of the subnet
    #[clap(long, value_parser=ic_cup_explorer::util::subnet_id_from_str)]
    pub subnet_id: SubnetId,

    /// The directory to download the latest CUP to
    #[clap(long)]
    pub download_path: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct VerifyArgs {
    /// The location of the CUP
    #[clap(long)]
    pub cup_path: PathBuf,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct CupExplorerArgs {
    #[clap(
        short = 'r',
        long,
        alias = "registry-url",
        default_value = "https://ic0.app"
    )]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    pub nns_url: Url,

    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

async fn explore(registry_url: Url, subnet_id: SubnetId, path: Option<PathBuf>) {
    let registry_canister = Arc::new(RegistryCanister::new(vec![registry_url]));

    println!("Fetching the list of nodes on subnet {}...", subnet_id);

    let node_records = get_nodes(&registry_canister, subnet_id).await;
    println!("Found {} node(s)", node_records.len());
    for (i, (id, record)) in node_records.iter().enumerate() {
        println!("  {:2}. {} ({})", i + 1, id, http_url(record));
    }

    println!("\nDetecting the latest CUP...");

    let tasks = node_records.into_iter().map(|(node_id, node)| {
        task::spawn(async move { (node_id, get_cup(&http_url(&node)).await) })
    });

    let mut latest_height = 0;
    let mut latest = None;

    for t in tasks {
        let (node_id, content) = t.await.unwrap();
        match content {
            Err(err) => {
                println!(" ✘ [{}]: {}", node_id, err);
            }
            Ok(None) => {
                println!(" ? [{}]: no cup yet", node_id);
            }
            Ok(Some(cup)) => {
                let content = pb::CatchUpContent::decode(&cup.content[..]).unwrap();
                let block = content.block.unwrap();
                let height = block.height;
                let hash = hex::encode(&content.state_hash[..]);
                let time = block.time;

                println!(
                    " ✔ [{}]: time = {}, height = {}, state_hash: {}",
                    node_id, time, height, hash
                );
                if height > latest_height {
                    latest_height = height;
                    latest = Some((node_id, cup));
                }
            }
        }
    }

    if let Some((node, cup)) = latest {
        let content = pb::CatchUpContent::decode(&cup.content[..]).unwrap();
        let block = content.block.unwrap();
        let hash = hex::encode(&content.state_hash[..]);
        let time = block.time;
        println!();
        println!("Latest state:");
        println!("{:>10}: {}", "TIME", time);
        println!("{:>10}: {}", "HEIGHT", latest_height);
        println!("{:>10}: {}", "HASH", hash);
        println!("{:>10}: {}", "NODE", node);

        if let Some(path) = path {
            let bytes = cup.encode_to_vec();
            println!("Writing cup to {:?}", path);
            fs::write(path, bytes)
                .await
                .expect("Failed to write bytes");
        }
    }
}

fn verify(nns_url: Url, cup_path: &Path) {
    let client = Arc::new(RegistryCanisterClient::new(nns_url));
    println!(
        "Registry client created. Latest registry version: {}",
        client.get_latest_version()
    );

    println!("\nCreating crypto component...");
    let (crypto_config, _tmp) = CryptoConfig::new_in_temp_dir();
    ic_crypto_node_key_generation::generate_node_keys_once(
        &crypto_config,
        Some(tokio::runtime::Handle::current()),
    )
    .expect("error generating node public keys");
    let client_clone = client.clone();
    let crypto = Arc::new(CryptoComponent::new(
        &crypto_config,
        Some(tokio::runtime::Handle::current()),
        client_clone,
        make_logger().into(),
        None,
    ));

    println!("\nReading CUP file at {:?}", cup_path);
    let bytes = std::fs::read(cup_path).expect("Failed to read file");
    let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).expect("Failed to decode bytes");
    let cup = CatchUpPackage::try_from(&proto_cup).expect("Failed to deserialize CUP content");

    if !cup.content.check_integrity() {
        panic!(
            "Integrity check of file {cup_path:?} failed. Payload: {:?}",
            cup.content.block.as_ref().payload.as_ref()
        );
    } else {
        println!("CUP integrity verified!");
    }

    let subnet_id = get_subnet_id(&cup).unwrap();
    println!("\nChecking CUP signature for subnet {}...", subnet_id);

    let block = cup.content.block.get_value();
    crypto
        .verify_combined_threshold_sig_by_public_key(
            &CombinedThresholdSigOf::new(CombinedThresholdSig(proto_cup.signature.clone())),
            &CatchUpContentProtobufBytes::from(&proto_cup),
            subnet_id,
            block.context.registry_version,
        )
        .map_err(|e| {
            println!(
                "Failed to verify CUP signature at: {:?} with: {:?}",
                cup_path, e
            )
        })
        .unwrap();
    println!("CUP signature verification successful!");

    let summary = block.payload.as_ref().as_summary();
    let dkg_version = summary.dkg.registry_version;

    println!("\nLatest subnet state according to CUP:");
    println!(
        "{:>20}: {}, ({})",
        "TIME",
        block.context.time.as_nanos_since_unix_epoch(),
        block.context.time
    );
    println!("{:>20}: {}", "HEIGHT", block.height);
    println!(
        "{:>20}: {}",
        "HASH",
        hex::encode(&cup.content.state_hash.get_ref().0[..])
    );
    println!("{:>20}: {}", "REGISTRY VERSION", dkg_version);

    println!("\nVerifying that the subnet was halted on this CUP...");
    let halted = client
        .get_halt_at_cup_height(subnet_id, dkg_version)
        .unwrap()
        .unwrap();
    assert!(
        halted,
        "Verification failed: Subnet wasn't instructed to halt on this CUP"
    );
    println!(
        "\nConfirmed that subnet {} was halted on this CUP.",
        subnet_id
    );
    println!("It may only be restarted via subnet recovery using the state hash listed above.");
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
        SubCommand::Verify(verify_args) => verify(args.nns_url, &verify_args.cup_path),
    }
}
