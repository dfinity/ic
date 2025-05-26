use clap::Parser;
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_cup_explorer::{create_registry, get_cup, get_subnet_id, make_logger};
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetRecord};
use ic_protobuf::types::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_keys::{make_node_record_key, make_subnet_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::consensus::{CatchUpContentProtobufBytes, CatchUpPackage};
use ic_types::crypto::{CombinedThresholdSig, CombinedThresholdSigOf};
use ic_types::{NodeId, PrincipalId, SubnetId};
use prost::Message;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use slog::{warn, Logger};
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
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
    #[clap(long, value_parser=subnet_id_from_str)]
    pub subnet_id: SubnetId,

    /// The directory to download the latest CUP to
    #[clap(long)]
    pub download_path: Option<PathBuf>,
}

pub fn subnet_id_from_str(s: &str) -> Result<SubnetId, String> {
    PrincipalId::from_str(s)
        .map_err(|e| format!("Unable to parse subnet_id {:?}", e))
        .map(SubnetId::from)
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct VerifyArgs {
    /// The location of the CUP
    #[clap(long)]
    pub cup_path: PathBuf,

    /// The location of the registry local store
    #[clap(long)]
    pub local_store: PathBuf,
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

/// Returns the list of nodes assigned to the specified subnet_id.
/// TODO: Ideally, we should use the local store instead, since these responses aren't certified
async fn get_nodes(
    registry_canister: &Arc<RegistryCanister>,
    subnet_id: SubnetId,
) -> Vec<(NodeId, NodeRecord)> {
    let (subnet_record, version) = registry_canister
        .get_value(make_subnet_record_key(subnet_id).as_bytes().to_vec(), None)
        .await
        .expect("failed to fetch the list of nodes");

    let subnet = SubnetRecord::decode(&subnet_record[..]).expect("failed to decode subnet record");

    let futures: Vec<_> = subnet
        .membership
        .into_iter()
        .map(|n| {
            let registry_canister = Arc::clone(registry_canister);
            task::spawn(async move {
                let node_id = NodeId::from(PrincipalId::try_from(&n[..]).unwrap());
                let (node_record_bytes, _) = registry_canister
                    .get_value(
                        make_node_record_key(node_id).as_bytes().to_vec(),
                        Some(version),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("failed to get node record {}: {}", node_id, e));
                let record = NodeRecord::decode(&node_record_bytes[..]).unwrap_or_else(|e| {
                    panic!("failed to deserialize node record {}: {}", node_id, e)
                });
                (node_id, record)
            })
        })
        .collect();

    let mut results = Vec::new();
    for f in futures {
        results.push(f.await.unwrap());
    }
    results
}

fn http_url(n: &NodeRecord) -> Url {
    let c = n.http.as_ref().unwrap();
    // Parse IP address (using IpAddr::parse())
    let ip_addr = c.ip_addr.parse().unwrap();
    Url::parse(
        format!(
            "http://{}",
            SocketAddr::new(ip_addr, u16::try_from(c.port).unwrap())
        )
        .as_str(),
    )
    .unwrap()
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
                let h = block.height;
                let s = hex::encode(&content.state_hash[..]);
                let t = block.time;

                println!(
                    " ✔ [{}]: time = {}, height = {}, state_hash: {}",
                    node_id, t, h, s
                );
                if h > latest_height {
                    latest_height = h;
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
            let file_path = path.join("cup.pb".to_string());
            println!("Writing cup to {:?}", file_path);
            fs::write(file_path, bytes)
                .await
                .expect("Failed to write bytes");
        }
    }
}

async fn verify(nns_url: Url, cup_path: &Path, local_store_path: &Path, logger: Logger) {
    // Create a registry local store
    let (_replicator, client) = create_registry(nns_url, local_store_path, logger.clone()).await;

    // Create a crypto component
    let (crypto_config, _tmp) = CryptoConfig::new_in_temp_dir();
    ic_crypto_node_key_generation::generate_node_keys_once(
        &crypto_config,
        Some(tokio::runtime::Handle::current()),
    )
    .expect("error generating node public keys");
    let replica_logger = logger.clone().into();
    let client_clone = client.clone();
    let crypto = tokio::task::spawn_blocking(move || {
        Arc::new(CryptoComponent::new(
            &crypto_config,
            Some(tokio::runtime::Handle::current()),
            client_clone,
            replica_logger,
            None,
        ))
    })
    .await
    .unwrap();

    // Read and parse the CUP
    let bytes = fs::read(cup_path).await.expect("Failed to read file");
    let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).expect("Failed to decode bytes");
    let cup = CatchUpPackage::try_from(&proto_cup).expect("Failed to deserialize CUP content");

    // Verify the CUP
    if !cup.content.check_integrity() {
        panic!(
            "Integrity check of file {cup_path:?} failed. Payload: {:?}",
            cup.content.block.as_ref().payload.as_ref()
        );
    }

    let subnet_id = get_subnet_id(&cup).unwrap();

    crypto
        .verify_combined_threshold_sig_by_public_key(
            &CombinedThresholdSigOf::new(CombinedThresholdSig(proto_cup.signature.clone())),
            &CatchUpContentProtobufBytes::from(&proto_cup),
            subnet_id,
            cup.content.block.get_value().context.registry_version,
        )
        .map_err(|e| {
            warn!(
                logger,
                "Failed to verify CUP signature at: {:?} with: {:?}", cup_path, e
            )
        })
        .unwrap();

    let block = cup.content.block.get_value();
    let summary = block.payload.as_ref().as_summary();
    let dkg_version = summary.dkg.registry_version;

    let halted = client
        .get_halt_at_cup_height(subnet_id, dkg_version)
        .unwrap()
        .unwrap();

    println!("Signature verification successful!");
    println!("Subnet ID: {}", subnet_id);
    println!("Height: {}", block.height);
    println!(
        "Time: {}, ({})",
        block.context.time.as_nanos_since_unix_epoch(),
        block.context.time
    );
    println!(
        "Hash: {}",
        hex::encode(&cup.content.state_hash.get_ref().0[..])
    );
    println!("DKG registry version: {}", dkg_version);
    println!("Subnet halted on this cup: {}", halted);
    assert!(
        halted,
        "Verification failed: Subnet wasn't instructed to halt on this CUP"
    );
}

#[tokio::main]
async fn main() {
    let logger = make_logger();
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
        SubCommand::Verify(verify_args) => {
            verify(
                args.nns_url,
                &verify_args.cup_path,
                &verify_args.local_store,
                logger,
            )
            .await
        }
    }
}
