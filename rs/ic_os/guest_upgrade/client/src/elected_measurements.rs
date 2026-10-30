use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use config_types::GuestOSConfig;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_pem_file;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::replica_version::ReplicaVersionRegistry;
use ic_registry_keys::make_replica_version_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_nns_data_provider_wrappers::CertifiedNnsDataProvider;
use ic_types::ReplicaVersion;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use prost::Message;
use tonic::async_trait;
use url::Url;

const NNS_PUBLIC_KEY_PATH: &str = "/run/config/nns_public_key.pem";

/// Upper bound on the time spent reading the record of a single GuestOS version. It leaves room
/// for the fallback to all elected versions within the systemd timeout (see
/// guest-upgrade-client.service)
const VERSION_RECORD_TIMEOUT: Duration = Duration::from_secs(60);

/// Delay between attempts to read the record of a single GuestOS version
const VERSION_RECORD_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Source of the launch measurements that the NNS elected for GuestOS versions
#[async_trait]
pub trait ElectedMeasurementsSource: Send + Sync {
    /// Returns the launch measurements of `guestos_version` at the latest registry version.
    /// Fails if `guestos_version` is not elected.
    async fn get_version_measurements(
        &self,
        guestos_version: &ReplicaVersion,
    ) -> Result<Vec<Vec<u8>>>;

    /// Returns the launch measurements of all GuestOS versions elected at the latest registry
    /// version.
    ///
    /// TODO: Remove once all GuestOSes are upgraded.
    async fn get_all_elected_measurements(&self) -> Result<Vec<Vec<u8>>>;
}

/// Reads elected launch measurements from the NNS registry canister
pub struct NnsElectedMeasurementsSource {
    nns_urls: Vec<Url>,
    nns_public_key: ThresholdSigPublicKey,
    registry_canister: RegistryCanister,
}

impl NnsElectedMeasurementsSource {
    pub fn new(guestos_config: &GuestOSConfig) -> Result<Self> {
        let nns_urls = guestos_config.icos_settings.nns_urls.clone();
        ensure!(!nns_urls.is_empty(), "No NNS URLs in the GuestOS config");

        let nns_public_key = parse_threshold_sig_key_from_pem_file(Path::new(NNS_PUBLIC_KEY_PATH))
            .context("Cannot read NNS public key")?;

        let registry_canister =
            RegistryCanister::new_with_agent_transformer(nns_urls.clone(), |agent| {
                agent.with_nns_public_key(nns_public_key)
            });

        Ok(Self {
            nns_urls,
            nns_public_key,
            registry_canister,
        })
    }

    /// Reads the latest value of `key`, retrying on errors other than that the key is missing
    async fn get_certified_value(&self, key: &str) -> Result<Option<Vec<u8>>> {
        loop {
            let result = self
                .registry_canister
                .get_value_with_update(key.as_bytes().to_vec(), None)
                .await;

            match result {
                Ok((value, _version)) => return Ok(Some(value)),
                Err(ic_registry_transport::Error::KeyNotPresent(_)) => return Ok(None),
                Err(err) => {
                    eprintln!("Failed to read {key} from the NNS registry, retrying: {err}");
                    tokio::time::sleep(VERSION_RECORD_RETRY_DELAY).await;
                }
            }
        }
    }
}

#[async_trait]
impl ElectedMeasurementsSource for NnsElectedMeasurementsSource {
    async fn get_version_measurements(
        &self,
        guestos_version: &ReplicaVersion,
    ) -> Result<Vec<Vec<u8>>> {
        let key = make_replica_version_key(guestos_version);
        let value = tokio::time::timeout(VERSION_RECORD_TIMEOUT, self.get_certified_value(&key))
            .await
            .with_context(|| {
                format!(
                    "Timed out reading {key} from the NNS registry after {VERSION_RECORD_TIMEOUT:?}"
                )
            })??
            .with_context(|| format!("GuestOS version '{guestos_version}' is not elected"))?;

        launch_measurements_from_registry_value(guestos_version, &value)
    }

    async fn get_all_elected_measurements(&self) -> Result<Vec<Vec<u8>>> {
        let registry_client = RegistryClientImpl::new(
            Arc::new(CertifiedNnsDataProvider::new(
                tokio::runtime::Handle::current(),
                self.nns_urls.clone(),
                self.nns_public_key,
            )),
            None,
        );

        registry_client
            .try_polling_latest_version(usize::MAX)
            .context("unable to poll Registry")?;

        let registry_version = registry_client.get_latest_version();
        registry_client
            .get_guest_launch_measurements(registry_version)
            .map_err(|e| anyhow!("Failed to get elected measurements from registry: {e}"))
    }
}

/// Returns the launch measurements in `value`, the registry value of the record of
/// `guestos_version`
pub fn launch_measurements_from_registry_value(
    guestos_version: &ReplicaVersion,
    value: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let record = ReplicaVersionRecord::decode(value).with_context(|| {
        format!("Failed to decode the registry record of GuestOS version {guestos_version}")
    })?;

    ensure!(
        record.replica_version_id == guestos_version.as_ref(),
        "The registry record of GuestOS version '{guestos_version}' is for version '{}'",
        record.replica_version_id
    );

    let launch_measurements = record
        .guest_launch_measurements
        .unwrap_or_default()
        .guest_launch_measurements
        .into_iter()
        .map(|measurement| measurement.measurement)
        .collect::<Vec<Vec<u8>>>();

    ensure!(
        !launch_measurements.is_empty(),
        "GuestOS version {guestos_version} has no launch measurements"
    );

    Ok(launch_measurements)
}
