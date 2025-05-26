use std::{env, path::Path, sync::Arc, time::Duration};

use ic_canister_client::{Agent, Sender};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_protobuf::types::v1 as pb;
use ic_registry_client::client::RegistryClientImpl;
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

/// Fetches the a CatchUp package, if it's present.
pub async fn get_cup(url: &Url) -> Result<Option<pb::CatchUpPackage>, String> {
    let agent = Agent::new(url.clone(), Sender::Anonymous);
    agent
        .query_cup_endpoint(None)
        .await
        .map_err(|e| format!("failed to get catch up package: {}", e))
}

// Create a full copy of the registry local store in the given path,
// by polling the `get_certified_changes_since` endpoint repeatedly
pub async fn create_registry(
    nns_url: Url,
    local_store_path: &Path,
    logger: Logger,
) -> (RegistryReplicator, Arc<RegistryClientImpl>) {
    let pem_bytes: &[u8] = include_bytes!("../ic_public_key.pem");
    // Write public keys to a temp file, because `parse_threshold_sig_key` expects a file path
    let mut temp_path = env::temp_dir();
    temp_path.push("ic_public_key.pem");
    let mut file = File::create(&temp_path).await.unwrap();
    file.write_all(pem_bytes).await.unwrap();

    let content = fs::read_to_string(&temp_path).await.unwrap();
    println!("NNS public key being used: \n{}", content);

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
    // Note: This will return immediately if the local store is non-empty
    registry_replicator
        .initialize_local_store(vec![nns_url.clone()], Some(nns_public_key))
        .await;
    registry_client.poll_once().unwrap();
    // Optimistically poll once more, in case the initial local store was non-empty
    // Note this will return at most 1000 registry deltas
    registry_replicator.poll(vec![nns_url]).await.unwrap();
    registry_client.poll_once().unwrap();
    (registry_replicator, registry_client)
}

/// Make a logger at info level
pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog::LevelFilter::new(drain, slog::Level::Info).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

// Returns the subnet id for the given CUP.
pub fn get_subnet_id(cup: &CatchUpPackage) -> Result<SubnetId, String> {
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
