use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use ic_canister_client::{Agent, Sender};
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::types::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{
    RegistryVersion, SubnetId,
    consensus::{CatchUpContentProtobufBytes, CatchUpPackage},
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, threshold_sig::ni_dkg::NiDkgTargetSubnet,
    },
};
use prost::Message;
use tokio::{fs, task};
use url::Url;

use crate::{
    registry::{RegistryCanisterClient, get_nodes},
    util::http_url,
};

pub mod registry;
pub mod util;

/// Fetches the contents of a CatchUp package, if it's present.
pub async fn get_catchup_content(url: &Url) -> Result<Option<pb::CatchUpContent>, String> {
    let maybe_cup = get_cup(url).await?;
    match maybe_cup {
        Some(cup) => {
            // TODO(roman): verify signatures?
            let content = pb::CatchUpContent::decode(&cup.content[..])
                .map_err(|e| format!("failed to deserialize cup: {e}"))?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

/// Fetches the CatchUp package, if it's present.
async fn get_cup(url: &Url) -> Result<Option<pb::CatchUpPackage>, String> {
    let agent = Agent::new(url.clone(), Sender::Anonymous);
    agent
        .query_cup_endpoint(None)
        .await
        .map_err(|e| format!("failed to get catch up package: {e}"))
}

/// Returns the subnet id for the given CUP.
fn get_subnet_id(cup: &CatchUpPackage) -> Result<SubnetId, String> {
    // Note that although sometimes CUPs have no signatures (e.g. genesis and
    // recovery CUPs) they always have the signer id (the DKG id), which is taken
    // from the high-threshold transcript when we build a genesis/recovery CUP.
    let dkg_id = &cup.signature.signer;
    // If the DKG key material was signed by the subnet itself — use it.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, then the local CUP is a genesis or recovery CUP of an application
        // subnet or of the NNS subnet recovered on failover nodes. We cannot derive the subnet id
        // from it.
        NiDkgTargetSubnet::Remote(_) => {
            Err("Registry CUPs cannot be verified with this tool".into())
        }
    }
}

/// Download the latest CUP of all nodes on the subnet at the latest registry version.
/// Optionally persist the latest CUP under the specified file path.
pub async fn explore(registry_url: Url, subnet_id: SubnetId, path: Option<PathBuf>) {
    let registry_canister = Arc::new(RegistryCanister::new(vec![registry_url]));

    println!("Fetching the list of nodes on subnet {subnet_id}...");

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
                println!(" ✘ [{node_id}]: {err}");
            }
            Ok(None) => {
                println!(" ? [{node_id}]: no cup yet");
            }
            Ok(Some(cup)) => {
                let content = pb::CatchUpContent::decode(&cup.content[..]).unwrap();
                let block = content.block.unwrap();
                let height = block.height;
                let hash = hex::encode(&content.state_hash[..]);
                let time = block.time;

                println!(" ✔ [{node_id}]: time = {time}, height = {height}, state_hash: {hash}");
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
            println!("Writing cup to {path:?}");
            fs::write(path, bytes).await.expect("Failed to write bytes");
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SubnetStatus {
    Running,
    Halted,
    Recovered,
}

/// 1. Verify the CUP against the subnet public key found in the registry
/// 2. Print the latest subnet state (time, height, state hash) according to the CUP
/// 3. Verify that the subnet was halted on this CUP (meaning the CUP represents the latest state)
/// 4. Search for a subsequent recover proposal that restarted the subnet, and confirm that the
///    correct parameters were used.
pub fn verify(nns_url: Url, nns_pem: Option<PathBuf>, cup_path: &Path) -> SubnetStatus {
    let client = Arc::new(RegistryCanisterClient::new(nns_url, nns_pem));
    let latest_version = client.get_latest_version();
    println!("Registry client created. Latest registry version: {latest_version}",);

    println!("\nCreating crypto component...");
    let client_clone = Arc::clone(&client);
    let crypto = Arc::new(ic_crypto_for_verification_only::new(client_clone));

    println!("\nReading CUP file at {cup_path:?}");
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
    println!("\nChecking CUP signature for subnet {subnet_id}...");

    let block = cup.content.block.get_value();
    crypto
        .verify_combined_threshold_sig_by_public_key(
            &CombinedThresholdSigOf::new(CombinedThresholdSig(proto_cup.signature.clone())),
            &CatchUpContentProtobufBytes::from(&proto_cup),
            subnet_id,
            block.context.registry_version,
        )
        .map_err(|e| format!("Failed to verify CUP signature at: {cup_path:?} with: {e:?}"))
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
    if !halted {
        return SubnetStatus::Running;
    }
    println!(
        "\nConfirmed that subnet {} was halted on this CUP as of {}.",
        subnet_id, block.context.time
    );
    println!(
        "This means that the CUP represents the latest state of the subnet while the subnet remains halted."
    );
    println!(
        "The subnet may ONLY be restarted via a recovery proposal using the same state hash as listed above."
    );

    println!("\nSearching for a recovery proposal...");
    for version in dkg_version.get() + 1..=latest_version.get() {
        let version = RegistryVersion::new(version);
        match client.get_cup_contents(subnet_id, version) {
            Ok(contents) => {
                if contents.value.is_some() && contents.version == version {
                    let cup_contents = contents.value.unwrap();
                    println!("Found Recovery proposal at version {version}:");
                    println!("{:>20}: {}", "TIME", cup_contents.time);
                    println!("{:>20}: {}", "HEIGHT", cup_contents.height);
                    println!(
                        "{:>20}: {}",
                        "HASH",
                        hex::encode(&cup_contents.state_hash[..])
                    );
                    println!("Ensuring recovery time is greater than CUP time...");
                    assert!(cup_contents.time > block.context.time.as_nanos_since_unix_epoch());
                    println!("Success!");
                    println!("Ensuring recovery height is greater than CUP height...");
                    assert!(cup_contents.height > block.height.get());
                    println!("Success!");
                    println!("Ensuring recovery state hash is equal to CUP state hash...");
                    assert_eq!(
                        cup_contents.state_hash[..],
                        cup.content.state_hash.get_ref().0[..]
                    );
                    println!("Success!");
                    println!(
                        "The subnet was correctly recovered without modifications to the state!"
                    );
                    return SubnetStatus::Recovered;
                } else {
                    println!("No Recovery proposal found at version {version}");
                }
            }
            Err(err) => {
                println!("Failed to fetch CUP contents at version {version}: {err}")
            }
        }
    }

    println!("The subnet has not been recovered yet.");
    println!(
        "A recovery proposal should specify a time and height that is greater than the time and height of the CUP above."
    );
    println!(
        "Additionally, the proposed state hash should be equal to the one in the provided CUP, to ensure there were no modifications to the state."
    );
    SubnetStatus::Halted
}
