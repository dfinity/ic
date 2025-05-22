use std::{env, path::Path, sync::Arc, time::Duration};

use ic_canister_client::{Agent, Sender};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::types::v1 as pb;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{
    consensus::CatchUpPackage, crypto::threshold_sig::ni_dkg::NiDkgTargetSubnet, SubnetId,
};
use prost::Message;
use reqwest::Url;
use slog::{o, Drain, Logger};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

/// Fetches the contents of a CatchUp package, if it's present.
pub async fn get_catchup_content(url: &Url) -> Result<Option<pb::CatchUpContent>, String> {
    let maybe_cup = get_cup(url).await?;
    match maybe_cup {
        Some(cup) => {
            // TODO(roman): verify signatures?
            let content = pb::CatchUpContent::decode(&cup.content[..])
                .map_err(|e| format!("failed to deserialize cup: {}", e))?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

pub async fn get_cup(url: &Url) -> Result<Option<pb::CatchUpPackage>, String> {
    let agent = Agent::new(url.clone(), Sender::Anonymous);
    agent
        .query_cup_endpoint(None)
        .await
        .map_err(|e| format!("failed to get catch up package: {}", e))
}

pub async fn create_registry(
    nns_url: Url,
    local_store_path: &Path,
    logger: Logger,
) -> (RegistryReplicator, Arc<RegistryClientImpl>) {
    let pem_bytes: &[u8] = include_bytes!("../ic_public_key.pem");
    let mut temp_path = env::temp_dir(); // Gets /tmp on Unix, or similar on Windows
    temp_path.push("ic_public_key.pem");
    let mut file = File::create(&temp_path).await.unwrap();
    file.write_all(pem_bytes).await.unwrap();

    let content = fs::read_to_string(&temp_path).await.unwrap();
    println!("{}", content);

    let nns_public_key = parse_threshold_sig_key(&temp_path).unwrap();

    let local_store = Arc::new(LocalStoreImpl::new(local_store_path));
    let registry_client = Arc::new(RegistryClientImpl::new(
        local_store.clone(),
        /*metrics_registry=*/ None,
    ));
    let registry_replicator = RegistryReplicator::new_with_clients(
        logger.into(),
        local_store,
        registry_client.clone(),
        Duration::from_secs(10),
    );
    registry_replicator
        .initialize_local_store(vec![nns_url.clone()], Some(nns_public_key))
        .await;
    registry_client.poll_once().unwrap();
    registry_replicator.poll(vec![nns_url]).await.unwrap();
    registry_client.poll_once().unwrap();
    (registry_replicator, registry_client)
}

pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog::LevelFilter::new(drain, slog::Level::Info).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

// Returns the subnet id for the given CUP.
pub fn get_subnet_id(
    registry: &dyn RegistryClient,
    cup: &CatchUpPackage,
) -> Result<SubnetId, String> {
    let dkg_summary = &cup
        .content
        .block
        .get_value()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    // Note that although sometimes CUPs have no signatures (e.g. genesis and
    // recovery CUPs) they always have the signer id (the DKG id), which is taken
    // from the high-threshold transcript when we build a genesis/recovery CUP.
    let dkg_id = &cup.signature.signer;
    // If the DKG key material was signed by the subnet itself — use it, if not, get
    // the subnet id from the registry.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, then the local CUP is a genesis or recovery CUP of an application
        // subnet or of the NNS subnet recovered on failover nodes. We cannot derive the subnet id
        // from it, so we use the registry version of that CUP and the node id of one of the
        // high-threshold committee members, to find out to which subnet this node belongs to.
        NiDkgTargetSubnet::Remote(_) => {
            let node_id = dkg_summary
                .current_transcripts()
                .values()
                .next()
                .ok_or("No current transcript found")?
                .committee
                .get()
                .iter()
                .next()
                .ok_or("No nodes in current transcript committee found")?;
            match registry.get_subnet_id_from_node_id(*node_id, dkg_summary.registry_version) {
                Ok(Some(subnet_id)) => Ok(subnet_id),
                other => Err(format!(
                    "Couldn't get the subnet id from the registry for node {:?} at registry version {}: {:?}",
                    node_id, dkg_summary.registry_version, other
                )),
            }
        }
    }
}
