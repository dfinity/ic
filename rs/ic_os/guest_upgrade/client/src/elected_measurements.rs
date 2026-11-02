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

/// Upper bound on a single attempt to read the record of a GuestOS version from one NNS
/// endpoint. An update call normally completes within a few seconds, but by default the agent
/// waits up to 6 minutes on an endpoint that stalls. Keeping each attempt well below
/// VERSION_RECORD_TIMEOUT leaves time for retries, each of which goes to a randomly chosen
/// endpoint
const VERSION_RECORD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

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

        Ok(Self::new_with_nns_public_key(nns_urls, nns_public_key))
    }

    /// Reads from the NNS at `nns_urls`, which must not be empty, and verifies the responses
    /// against `nns_public_key`
    fn new_with_nns_public_key(nns_urls: Vec<Url>, nns_public_key: ThresholdSigPublicKey) -> Self {
        let registry_canister =
            RegistryCanister::new_with_agent_transformer(nns_urls.clone(), |agent| {
                agent
                    .with_nns_public_key(nns_public_key)
                    .with_ingress_timeout(VERSION_RECORD_ATTEMPT_TIMEOUT)
            });

        Self {
            nns_urls,
            nns_public_key,
            registry_canister,
        }
    }

    /// Reads the latest value of `key`, retrying on errors other than that the key is missing.
    /// Each attempt goes to a randomly chosen NNS endpoint, and the agent gives up on it after
    /// VERSION_RECORD_ATTEMPT_TIMEOUT
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

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Encode;
    use ic_certification_test_utils::generate_root_of_trust;
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
    use ic_nns_constants::REGISTRY_CANISTER_ID;
    use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_registry_wasm};
    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurements,
    };
    use ic_registry_transport::insert;
    use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
    use pocket_ic::PocketIcBuilder;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// Starts an NNS endpoint that accepts connections but never answers, like a node that
    /// stalls. Returns its URL and the number of connections it has accepted so far.
    async fn start_stalled_endpoint() -> (Url, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();

        let connection_count = Arc::new(AtomicUsize::new(0));
        let accepted_connection_count = connection_count.clone();
        tokio::spawn(async move {
            // Kept open, so that the client keeps waiting for an answer
            let mut connections = vec![];
            while let Ok((connection, _peer_address)) = listener.accept().await {
                accepted_connection_count.fetch_add(1, Ordering::Relaxed);
                connections.push(connection);
            }
        });

        (url, connection_count)
    }

    #[tokio::test]
    async fn test_reads_elected_measurements_from_nns_registry() {
        // Step 1: Prepare the world.

        // Step 1.1: Elect one GuestOS version in an initial registry that satisfies the
        // registry's invariants (which are checked when the Registry canister is installed).
        let elected_version = ReplicaVersion::try_from("elected_version").unwrap();
        let unelected_version = ReplicaVersion::try_from("unelected_version").unwrap();
        let launch_measurements = vec![vec![1_u8; 48], vec![2_u8; 48]];
        let elected_version_record = ReplicaVersionRecord {
            replica_version_id: elected_version.to_string(),
            release_package_sha256_hex: String::new(),
            release_package_urls: vec![],
            guest_launch_measurements: Some(GuestLaunchMeasurements {
                guest_launch_measurements: launch_measurements
                    .iter()
                    .map(|measurement| GuestLaunchMeasurement {
                        measurement: measurement.clone(),
                        metadata: None,
                    })
                    .collect(),
            }),
        };

        let mut nns_configuration = NnsInitPayloadsBuilder::new();
        let registry_init_args = nns_configuration
            .with_initial_invariant_compliant_mutations()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: vec![insert(
                    make_replica_version_key(&elected_version),
                    elected_version_record.encode_to_vec(),
                )],
                preconditions: vec![],
            }])
            .build()
            .registry;

        // Step 1.2: Create a simulated ICP (to wit, PocketIc), and install the Registry canister
        // on it.
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        install_canister(
            &pocket_ic,
            "Registry",
            REGISTRY_CANISTER_ID,
            Encode!(&registry_init_args).unwrap(),
            build_registry_wasm(),
            Some(REGISTRY_CANISTER_ID.get()),
        )
        .await;

        // Step 1.3: Read from pocket_ic, verifying its responses against the key that signs its
        // certificates.
        let nns_url = pocket_ic.make_live(None).await;
        let root_key_der = pocket_ic
            .root_key()
            .await
            .expect("PocketIc has no root key");
        let nns_public_key = parse_threshold_sig_key_from_der(&root_key_der).unwrap();
        let source =
            NnsElectedMeasurementsSource::new_with_nns_public_key(vec![nns_url], nns_public_key);

        // Step 2: Call the code under test.

        let elected_result = source.get_version_measurements(&elected_version).await;
        let unelected_result = source.get_version_measurements(&unelected_version).await;

        // Step 3: Verify result(s).

        assert_eq!(elected_result.unwrap(), launch_measurements);

        let error = unelected_result.unwrap_err();
        assert!(format!("{error:#}").contains("is not elected"), "{error:#}");
    }

    /// An attempt on a stalled NNS endpoint is abandoned well within VERSION_RECORD_TIMEOUT, so
    /// that there is time left to retry on the other endpoints
    #[tokio::test]
    async fn test_abandons_stalled_endpoint_after_attempt_timeout() {
        // Step 1: Prepare the world.

        let (stalled_url, connection_count) = start_stalled_endpoint().await;
        let (nns_public_key, _nns_secret_key) = generate_root_of_trust(&mut rand::thread_rng());
        let source = NnsElectedMeasurementsSource::new_with_nns_public_key(
            vec![stalled_url],
            nns_public_key,
        );
        let key = make_replica_version_key(ReplicaVersion::try_from("stalled_version").unwrap());

        // Step 2: Call the code under test: a single attempt to read the record. Without
        // VERSION_RECORD_ATTEMPT_TIMEOUT, the agent would wait for 6 minutes; the outer timeout
        // makes such a regression fail quickly.

        let start = Instant::now();
        let result = tokio::time::timeout(
            VERSION_RECORD_TIMEOUT,
            source
                .registry_canister
                .get_value_with_update(key.into_bytes(), None),
        )
        .await;
        let elapsed = start.elapsed();

        // Step 3: Verify result(s).

        let attempt_result =
            result.expect("The attempt was not abandoned within VERSION_RECORD_TIMEOUT");
        assert!(attempt_result.is_err(), "{attempt_result:?}");
        assert!(
            elapsed >= VERSION_RECORD_ATTEMPT_TIMEOUT,
            "The attempt failed after only {elapsed:?}: {attempt_result:?}"
        );
        assert!(
            elapsed < VERSION_RECORD_ATTEMPT_TIMEOUT + Duration::from_secs(5),
            "The attempt took {elapsed:?}"
        );
        assert!(connection_count.load(Ordering::Relaxed) >= 1);
    }
}
