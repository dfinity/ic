use crate::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::read_file,
    util::{block_on, write_public_key_to_file},
};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_utils_threshold_sig_der::{parse_threshold_sig_key, public_key_to_der};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_client_helpers::{routing_table::RoutingTableRegistry, subnet::SubnetRegistry};
use ic_registry_keys::{make_crypto_threshold_signing_pubkey_key, make_subnet_list_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_replicator::RegistryReplicator;
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use ic_registry_subnet_features::ChainKeyConfig;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use prost::Message;
use slog::{Logger, error, info, warn};
use url::Url;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub type VersionedRecoveryResult<T> = RecoveryResult<(RegistryVersion, Option<T>)>;

#[derive(Clone)]
/// Enum instructing when we should call [RegistryReplicator::poll].
pub enum RegistryPollingStrategy {
    /// With this option we will only call [RegistryReplicator:poll] once, implicitly, during the
    /// initialization.
    OnlyOnInit,
    /// With this option we will call [RegistryReplicator:poll] every time we want to access the
    /// registry.
    WithEveryRead,
}

/// Wrapper around [RegistryReplicator] which simplifies accessing the *locally* stored registry.
///
/// 1. All errors are mapped to [RecoveryError];
/// 2. All get_* methods return an error, when [RegistryClient] returns `Ok(None)`;
/// 3. Depending on the [RegistryPollingStrategy], we might call [RegistryReplicator:poll] each
///    time a get_* method is called, before accessing the registry.
#[derive(Clone)]
pub struct RegistryHelper {
    registry_replicator: Arc<RegistryReplicator>,
    polling_strategy: RegistryPollingStrategy,
}

impl RegistryHelper {
    pub fn new(
        logger: Logger,
        nns_url: Url,
        local_store_path: PathBuf,
        nns_pem_path: &Path,
        polling_strategy: RegistryPollingStrategy,
    ) -> Self {
        let nns_pub_key = get_nns_public_key(&nns_url, nns_pem_path, &logger)
            .inspect_err(|err| error!(logger, "Failed getting the NNS public key: {}", err))
            .ok();
        let registry_replicator = Arc::new(block_on(RegistryReplicator::new(
            logger.clone().into(),
            &local_store_path,
            Duration::from_secs(10),
            vec![nns_url],
            nns_pub_key,
        )));

        Self {
            registry_replicator,
            polling_strategy,
        }
    }

    /// Returns the underlying [RegistryClient].
    pub fn registry_client(&self) -> Arc<dyn RegistryClient> {
        self.registry_replicator.get_registry_client()
    }

    /// Returns the node ids of the given subnet.
    pub fn get_node_ids_on_subnet(
        &self,
        subnet_id: SubnetId,
    ) -> VersionedRecoveryResult<Vec<NodeId>> {
        self.get(|registry_version, registry_client| {
            registry_client.get_node_ids_on_subnet(subnet_id, registry_version)
        })
    }

    /// Returns Chain key config of the given subnet
    pub fn get_chain_key_config(
        &self,
        subnet_id: SubnetId,
    ) -> VersionedRecoveryResult<ChainKeyConfig> {
        self.get(|registry_version, registry_client| {
            registry_client.get_chain_key_config(subnet_id, registry_version)
        })
    }

    /// Returns the [SubnetRecord] of the given subnet.
    pub fn get_subnet_record(&self, subnet_id: SubnetId) -> VersionedRecoveryResult<SubnetRecord> {
        self.get(|registry_version, registry_client| {
            registry_client.get_subnet_record(subnet_id, registry_version)
        })
    }

    /// Returns the list of canister migrations.
    pub fn get_canister_migrations(&self) -> VersionedRecoveryResult<CanisterMigrations> {
        self.get(|registry_version, registry_client| {
            registry_client.get_canister_migrations(registry_version)
        })
    }

    /// Returns the [RoutingTable].
    pub fn get_routing_table(&self) -> VersionedRecoveryResult<RoutingTable> {
        self.get(|registry_version, registry_client| {
            registry_client.get_routing_table(registry_version)
        })
    }

    /// Polls the [RegistryReplicator] for the most recent version of the registry and then
    /// gets the latest registry version.
    pub fn latest_registry_version(&self) -> RecoveryResult<RegistryVersion> {
        match self.polling_strategy {
            RegistryPollingStrategy::WithEveryRead => {
                block_on(self.registry_replicator.poll()).map_err(|err| {
                    RecoveryError::RegistryError(format!(
                        "Failed to poll the newest registry: {err}",
                    ))
                })?;
            }
            RegistryPollingStrategy::OnlyOnInit => {}
        }

        Ok(self.registry_client().get_latest_version())
    }

    /// Polls the [RegistryReplicator] for the most recent version of the registry and then
    /// extracts the appropriate entries based on the provided closure.
    fn get<T>(
        &self,
        field_extractor: impl Fn(RegistryVersion, Arc<dyn RegistryClient>) -> RegistryClientResult<T>,
    ) -> VersionedRecoveryResult<T> {
        let registry_version = self.latest_registry_version()?;

        let field = field_extractor(registry_version, self.registry_client()).map_err(|err| {
            RecoveryError::RegistryError(format!("Failed to extract the field: {err}"))
        })?;

        Ok((registry_version, field))
    }
}

fn get_nns_public_key(
    nns_url: &Url,
    nns_pem_path: &Path,
    logger: &Logger,
) -> RecoveryResult<ThresholdSigPublicKey> {
    if nns_pem_path.exists() {
        info!(
            logger,
            "{} exists, skipping download of NNS public key",
            nns_pem_path.display(),
        );
    } else {
        download_nns_pem(nns_url, nns_pem_path, logger)?;
    }

    let key = parse_threshold_sig_key(nns_pem_path)
        .map_err(|e| RecoveryError::RegistryError(format!("Failed to read nns.pem file: {e}")))?;

    let downloaded_key = read_file(nns_pem_path)
        .map_err(|e| RecoveryError::RegistryError(format!("Failed to read nns.pem: {e}")))?;
    info!(logger, "Continuing with public key:\n{}", downloaded_key);

    let included_key = include_str!("../ic_public_key.pem");

    if downloaded_key == included_key {
        info!(
            logger,
            "Downloaded key and included NNS public key are equal!"
        )
    } else {
        warn!(
            logger,
            "Downloaded key is NOT equal to included NNS public key"
        )
    }

    Ok(key)
}

fn download_nns_pem(nns_url: &Url, nns_pem_path: &Path, logger: &Logger) -> RecoveryResult<()> {
    info!(logger, "Downloading NNS public key...");
    let registry_canister = RegistryCanister::new(vec![nns_url.clone()]);

    let bytes =
        get_value_from_registry_canister(&registry_canister, make_subnet_list_record_key())?;

    let list = SubnetListRecord::decode(bytes.as_slice()).map_err(|e| {
        RecoveryError::RegistryError(format!("Error decoding subnet list from registry: {e}"))
    })?;

    let maybe_id = list.subnets.first().map(|x| {
        SubnetId::from(
            PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
        )
    });

    let key = maybe_id
        .map(make_crypto_threshold_signing_pubkey_key)
        .ok_or_else(|| RecoveryError::RegistryError("No subnets in list".to_string()))?;

    let bytes = get_value_from_registry_canister(&registry_canister, key)?;

    let public_key = PublicKey::decode(bytes.as_slice()).map_err(|e| {
        RecoveryError::RegistryError(format!("Error decoding PublicKey from registry: {e}"))
    })?;

    let key = ThresholdSigPublicKey::try_from(public_key).map_err(|e| {
        RecoveryError::RegistryError(format!(
            "failed to parse threshold signature PK from protobuf: {e:?}"
        ))
    })?;
    let der_bytes = public_key_to_der(&key.into_bytes()).map_err(|e| {
        RecoveryError::RegistryError(format!(
            "failed to encode threshold signature PK into DER: {e:?}"
        ))
    })?;

    write_public_key_to_file(&der_bytes, nns_pem_path)
}

fn get_value_from_registry_canister(
    registry_canister: &RegistryCanister,
    key: String,
) -> RecoveryResult<Vec<u8>> {
    block_on(registry_canister.get_value(key.as_bytes().to_vec(), /*version_opt=*/ None))
        .map_err(|e| {
            RecoveryError::RegistryError(format!(
                "Error getting value from the registry canister: {e}"
            ))
        })
        .map(|(bytes, _)| bytes)
}
