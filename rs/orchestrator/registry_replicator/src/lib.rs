//! # Registry Replicator
//!
//! (1) It polls one of the NNS Nodes for registry updates on a regular basis,
//! verifies the response using the public key configured in the registry and
//! applies the received changelog to the Registry Local Store.
//!
//! (2) In case of a "switch-over" or starting a new independent NNS subnet, the
//! Registry Replicator modifies the Registry Local Store before rebooting:
//!
//! Consider the registry of the «parent» IC instance as the source registry.
//! Let subnet_record be a subnet record (in the source registry) with
//! subnet_record.start_as_nns set to true. Let v be the registry version at
//! which subnet_record was added to the registry (i.e. the smallest v for which
//! subnet_record exists). Create a fresh (target) registry state that contains
//! all versions up to and including v-1. Add version v, but with the following
//! changes:
//! * subnet_record.start_as_nns is unset on all subnet records
//! * nns_subnet_id set to the new nns subnet id
//! * subnet_list: contains only the nns_subnet_id
//! * routing table: consists of a single entry that maps the same range of
//!   canister ids that was mapped to the NNS in the source registry to the
//!   subnet id obtained from subnet record
//!
//! # Concurrency
//!
//! This is the only component that writes to the Registry Local Store. While
//! individual changelog entries are stored atomically when replicating the
//! registry, the switch-over is *not* atomic. This is the reason why the
//! switch-over is handled in this component.

use crate::internal_state::{InternalState, write_certified_changes_to_local_store};
use ic_config::{
    Config,
    metrics::{Config as MetricsConfig, Exporter},
};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_interfaces_registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{ReplicaLogger, debug, error, info, warn};
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::{LocalStore, LocalStoreImpl};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{
    NodeId, RegistryVersion, crypto::threshold_sig::ThresholdSigPublicKey,
    registry::RegistryClientError,
};
use metrics::RegistryReplicatorMetrics;
use std::{
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

pub mod args;
mod internal_state;
pub mod metrics;
pub mod mock;

/// Trait for registry replication functionality.
/// This allows for mocking the registry replicator in tests.
#[async_trait::async_trait]
pub trait RegistryReplicatorTrait: Send + Sync {
    /// Polls the registry once, fetching and applying updates.
    async fn poll(&self) -> Result<(), String>;

    /// Returns the registry client used by this replicator.
    fn get_registry_client(&self) -> Arc<dyn RegistryClient>;

    /// Returns the local store used by this replicator.
    fn get_local_store(&self) -> Arc<dyn LocalStore>;

    /// Stops polling and sets the local registry data to what is contained in the provided local store.
    async fn stop_polling_and_set_local_registry_data(&self, new_local_store: &dyn LocalStore);
}

trait PollableRegistryClient: RegistryClient {
    /// Polls the registry once, updating its cache by polling the latest local store changes.
    fn poll_once(&self) -> Result<(), RegistryClientError>;
}

impl PollableRegistryClient for RegistryClientImpl {
    fn poll_once(&self) -> Result<(), RegistryClientError> {
        self.poll_once()
    }
}

pub struct RegistryReplicator {
    logger: ReplicaLogger,
    node_id: Option<NodeId>,
    config_nns_urls: Vec<Url>,
    config_nns_pub_key: Option<ThresholdSigPublicKey>,
    registry_client: Arc<dyn PollableRegistryClient>,
    local_store: Arc<dyn LocalStore>,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    poll_delay: Duration,
    metrics: Arc<RegistryReplicatorMetrics>,
}

impl RegistryReplicator {
    /// Creates a new instance of the registry replicator.
    /// This function will not return until the local store is initialized.
    async fn new_impl<P: AsRef<Path>>(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        local_store_path: P,
        poll_delay: Duration,
        metrics_registry: MetricsRegistry,
        config_nns_urls: Vec<Url>,
        config_nns_pub_key: Option<ThresholdSigPublicKey>,
    ) -> Self {
        let local_store = Arc::new(LocalStoreImpl::new(&local_store_path));
        std::fs::create_dir_all(local_store_path)
            .expect("Could not create directory for registry local store.");

        // Initialize the registry local store. Will not return if the nns is not
        // reachable.
        Self::initialize_local_store(
            &logger,
            local_store.clone(),
            config_nns_urls.clone(),
            config_nns_pub_key,
        )
        .await;

        let registry_client = Arc::new(RegistryClientImpl::new(
            local_store.clone(),
            Some(&metrics_registry),
        ));

        // Initialize the registry client with the latest version from the local store.
        if let Err(err) = registry_client.poll_once() {
            error!(
                logger,
                "Failed to poll the registry once after initialization: {}", err
            )
        }

        let metrics = Arc::new(RegistryReplicatorMetrics::new(&metrics_registry));

        Self {
            logger,
            node_id,
            config_nns_urls,
            config_nns_pub_key,
            registry_client,
            local_store,
            started: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            poll_delay,
            metrics,
        }
    }

    /// Creates a new instance of the registry replicator from the local store path, NNS URLs and
    /// root public key.
    /// This function will not return until the local store is initialized.
    pub async fn new<P: AsRef<Path>>(
        logger: ReplicaLogger,
        local_store_path: P,
        poll_delay: Duration,
        config_nns_urls: Vec<Url>,
        config_nns_pub_key: Option<ThresholdSigPublicKey>,
    ) -> Self {
        Self::new_impl(
            logger,
            None,
            local_store_path,
            poll_delay,
            MetricsRegistry::new(),
            config_nns_urls,
            config_nns_pub_key,
        )
        .await
    }

    /// Creates a new instance of the registry replicator from the node configuration.
    /// This function will not return until the local store is initialized.
    pub async fn new_from_config(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        config: &Config,
    ) -> Self {
        let (config_nns_urls, config_nns_pub_key) =
            Self::parse_registry_access_info_from_config(&logger, config);

        Self::new_impl(
            logger,
            node_id,
            &config.registry_client.local_store,
            Duration::from_millis(config.nns_registry_replicator.poll_delay_duration_ms),
            MetricsRegistry::global(),
            config_nns_urls,
            config_nns_pub_key,
        )
        .await
    }

    /// Creates a new instance of the registry replicator from the node configuration and a custom
    /// metrics address.
    /// This function will not return until the local store is initialized.
    pub async fn new_with_metrics_runtime(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        config: &Config,
        metrics_addr: SocketAddr,
    ) -> (Self, MetricsHttpEndpoint) {
        let metrics_config = MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
            ..Default::default()
        };
        let metrics_endpoint = MetricsHttpEndpoint::new(
            tokio::runtime::Handle::current(),
            metrics_config,
            MetricsRegistry::global(),
            &logger.inner_logger.root,
        );

        let replicator = RegistryReplicator::new_from_config(logger, node_id, config).await;

        (replicator, metrics_endpoint)
    }

    /// Return NNS [`Url`]s and [`ThresholdSigPublicKey`] if configured
    fn parse_registry_access_info_from_config(
        logger: &ReplicaLogger,
        config: &Config,
    ) -> (Vec<Url>, Option<ThresholdSigPublicKey>) {
        let nns_urls = match &config.registration.nns_url {
            None => {
                info!(logger, "No NNS Url is configured.");
                vec![]
            }
            Some(string) => string
                .split(',')
                .flat_map(|s| match Url::parse(s) {
                    Err(e) => {
                        info!(
                            logger,
                            "Could not parse registration NNS url from config: {}", e
                        );
                        None
                    }
                    Ok(url) => Some(url),
                })
                .collect::<Vec<Url>>(),
        };

        let nns_pub_key = match &config.registration.nns_pub_key_pem {
            None => {
                info!(logger, "No NNS public key is configured.");
                None
            }
            Some(path) => match parse_threshold_sig_key(path) {
                Err(e) => {
                    info!(
                        logger,
                        "Could not parse configured NNS Public Key file: {}", e
                    );
                    None
                }
                Ok(key) => Some(key),
            },
        };

        (nns_urls, nns_pub_key)
    }

    async fn initialize_local_store(
        logger: &ReplicaLogger,
        local_store: Arc<dyn LocalStore>,
        nns_urls: Vec<Url>,
        nns_pub_key: Option<ThresholdSigPublicKey>,
    ) {
        // If the local registry store is not empty, exit.
        if !local_store
            .get_changelog_since_version(ZERO_REGISTRY_VERSION)
            .expect("Could not read registry local store.")
            .is_empty()
        {
            info!(
                logger,
                "Local registry store is not empty, skipping initialization."
            );
            return;
        }

        let nns_pub_key =
            nns_pub_key.expect("Registry Local Store is empty and no NNS Public Key is provided.");
        let mut registry_version = ZERO_REGISTRY_VERSION;
        let mut timeout = 1;

        let registry_canister = RegistryCanister::new(nns_urls);

        // Fill the local registry store by polling the registry canister until we get no
        // more changes.
        loop {
            match write_certified_changes_to_local_store(
                &registry_canister,
                &nns_pub_key,
                local_store.as_ref(),
                registry_version,
            )
            .await
            {
                Ok(last_stored_version) => {
                    if last_stored_version == registry_version {
                        // The last stored version is the same as the requested version, which
                        // means we fetched the latest version.
                        break;
                    }

                    info!(
                        logger,
                        "Stored registry versions up to: {}", last_stored_version
                    );
                    registry_version = last_stored_version;
                    timeout = 1;
                }
                Err(e) => {
                    warn!(
                        logger,
                        "Couldn't fetch registry updates (retry in {}s): {:?}", timeout, e
                    );
                    tokio::time::sleep(Duration::from_secs(timeout)).await;
                    timeout *= 2;
                    timeout = timeout.min(60); // limit the timeout by a minute max
                }
            }
        }

        info!(
            logger,
            "Finished local store initialization at registry version: {}", registry_version
        );
    }

    /// Initializes the registry local store asynchronously and returns a future that
    /// continuously polls for registry updates.
    pub fn start_polling(
        &self,
        cancellation_token: CancellationToken,
    ) -> Result<impl Future<Output = ()> + use<>, Error> {
        if self.started.swap(true, Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "'start_polling' was already called",
            ));
        }

        let mut internal_state = InternalState::new(
            self.logger.clone(),
            self.node_id,
            self.registry_client.clone(),
            self.local_store.clone(),
            self.config_nns_urls.clone(),
            self.config_nns_pub_key,
            self.poll_delay,
        );

        let logger = self.logger.clone();
        let metrics = Arc::clone(&self.metrics);
        let registry_client = Arc::clone(&self.registry_client);
        let cancelled = Arc::clone(&self.cancelled);
        let started = Arc::clone(&self.started);
        let poll_delay = self.poll_delay;

        let future = async move {
            // TODO: consider having only one way of cancelling this future,
            // instead of having both `cancelled` and `cancellation_token`.
            while !cancelled.load(Ordering::Relaxed) {
                let timer = metrics.poll_duration.start_timer();
                // The relevant I/O-operation of the poll() function is querying
                // a node on the NNS for updates. As we set the query timeout to
                // `poll_delay` when constructing the underlying
                // `RegistryCanister` abstraction, we are guaranteed that
                // `poll()` returns after a maximal duration of `poll_delay`.
                if let Err(msg) = internal_state.poll().await {
                    warn!(logger, "Polling the NNS registry failed: {}", msg);
                    metrics.poll_count.with_label_values(&["error"]).inc();
                } else {
                    debug!(logger, "Polling the NNS succeeded.");
                    metrics.poll_count.with_label_values(&["success"]).inc();
                }
                timer.observe_duration();

                // Update the registry client with the latest changes.
                if let Err(msg) = registry_client.poll_once() {
                    warn!(logger, "Registry client failed to poll: {}", msg);
                }

                metrics
                    .registry_version
                    .set(registry_client.get_latest_version().get() as i64);

                tokio::select! {
                   _ = tokio::time::sleep(poll_delay) => {}
                   _ = cancellation_token.cancelled() => break
                };
            }

            started.store(false, Ordering::Relaxed);
        };

        Ok(future)
    }

    /// Requests latest version and certified changes from the [`RegistryCanister`] and applies
    /// changes to [`LocalStore`] and [`RegistryClient`] accordingly.
    ///
    /// Note that we will poll at most 1000 oldest registry versions (see the implementation of
    /// `get_certified_changes_since` of `RegistryCanister`), so multiple polls might be necessary
    /// to get the most recent version of the registry.
    pub async fn poll(&self) -> Result<(), String> {
        let poll_result = InternalState::new(
            self.logger.clone(),
            self.node_id,
            self.registry_client.clone(),
            self.local_store.clone(),
            self.config_nns_urls.clone(),
            self.config_nns_pub_key,
            self.poll_delay,
        )
        .poll()
        .await;

        // Update the registry client with the latest changes, regardless of whether
        // the polling succeeded or failed. Return any error from either operation.
        poll_result.and(self.registry_client.poll_once().map_err(|e| e.to_string()))
    }

    /// Set the local registry data to what is contained in the provided local store.
    ///
    /// IMPORTANT: This function does not update the registry client cache (i.e. does not call
    /// `poll_once` on it). This means that the latter will continue to serve data from the old
    /// local store after this function returns.
    /// It is not sufficient to call `poll_once` on the registry client here, because the latter
    /// only fetches changes since the latest known version, which would work only if the current
    /// local store is a prefix of the new one.
    /// Because this might not be the case (e.g. during NNS recovery on failover nodes), the caller
    /// is responsible for polling the registry client (if the current local store is a prefix of
    /// the new one) or for creating a new registry client, if needed.
    pub async fn stop_polling_and_set_local_registry_data(&self, source_registry: &dyn LocalStore) {
        self.stop_polling();
        // Wait until polling has actually stopped.
        while self.is_polling() {
            tokio::time::sleep(self.poll_delay).await;
        }

        // Read the registry data.
        let changelog = source_registry
            .get_changelog_since_version(RegistryVersion::from(0))
            .expect("Could not read changelog from source registry.");

        // Reset the local store and fill it with the read registry data.
        self.local_store
            .clear()
            .expect("Could not clear registry local store");
        for (v, cle) in changelog.into_iter().enumerate() {
            self.local_store
                .store(RegistryVersion::from((v + 1) as u64), cle)
                .expect("Could not store change log entry");
        }
    }

    /// Instruct the replicator to stop polling for registry updates.
    /// This does not wait for the polling to actually stop: An ongoing poll might still be in
    /// progress, potentially modifying the local store after this function returns. Though, it is
    /// guaranteed that new polls will not be started some time after this function returns, and
    /// that the Future returned by `start_polling` will eventually complete.
    pub fn stop_polling(&self) {
        self.cancelled.fetch_or(true, Ordering::Relaxed);
    }

    pub fn is_polling(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    pub fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        self.registry_client.clone()
    }

    pub fn get_local_store(&self) -> Arc<dyn LocalStore> {
        self.local_store.clone()
    }

    pub fn get_poll_delay(&self) -> Duration {
        self.poll_delay
    }
}

impl Drop for RegistryReplicator {
    fn drop(&mut self) {
        self.stop_polling();
    }
}

#[async_trait::async_trait]
impl RegistryReplicatorTrait for RegistryReplicator {
    async fn poll(&self) -> Result<(), String> {
        self.poll().await
    }

    fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        self.get_registry_client()
    }

    fn get_local_store(&self) -> Arc<dyn LocalStore> {
        self.get_local_store()
    }

    async fn stop_polling_and_set_local_registry_data(&self, new_local_store: &dyn LocalStore) {
        self.stop_polling_and_set_local_registry_data(new_local_store).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
    use ic_registry_local_store::{Changelog, KeyMutation, LocalStoreWriter};
    use ic_test_utilities_logger::with_test_replica_logger;
    use rand::{Rng, RngCore};
    use tempfile::TempDir;

    const INIT_NUM_VERSIONS: usize = 5;
    const TEST_POLL_DELAY: Duration = Duration::from_secs(1);

    // Function duplicate in registry_replicator/tests/test.rs
    fn random_init(local_store_path: &Path, n: usize, rng: &mut ReproducibleRng) {
        fn key_mutation(k: usize, rng: &mut ReproducibleRng) -> KeyMutation {
            let s = rng.next_u64() & 64;
            let set: bool = rng.r#gen();
            KeyMutation {
                key: k.to_string(),
                value: if set {
                    Some((0..s as u8).collect())
                } else {
                    None
                },
            }
        }

        let random_changelog = (0..n)
            .map(|_i| {
                let k = rng.r#gen::<usize>() % 64 + 1;
                (0..k).map(|k| key_mutation(k, rng)).collect()
            })
            .collect::<Changelog>();

        let store = LocalStoreImpl::new(local_store_path);
        for (i, c) in random_changelog.iter().enumerate() {
            store
                .store(RegistryVersion::from((i + 1) as u64), c.clone())
                .unwrap()
        }
    }

    async fn new_locally_initialized_replicator(num_versions_to_init: usize) -> RegistryReplicator {
        let local_store_path = TempDir::new().unwrap().keep();

        random_init(
            &local_store_path,
            num_versions_to_init,
            &mut reproducible_rng(),
        );

        with_test_replica_logger(|logger| {
            RegistryReplicator::new(logger, local_store_path, TEST_POLL_DELAY, vec![], None)
        })
        .await
    }

    #[tokio::test]
    async fn test_new_replicator_works_on_initialized_store_and_client_sees_it() {
        let replicator = new_locally_initialized_replicator(INIT_NUM_VERSIONS).await;
        assert_eq!(
            replicator.registry_client.get_latest_version(),
            RegistryVersion::from(INIT_NUM_VERSIONS as u64)
        );
    }

    #[tokio::test]
    async fn test_set_stop_polling_and_set_local_registry_data_works() {
        let source = new_locally_initialized_replicator(2 * INIT_NUM_VERSIONS).await;
        let target = new_locally_initialized_replicator(INIT_NUM_VERSIONS).await;

        target
            .stop_polling_and_set_local_registry_data(source.get_local_store().as_ref())
            .await;
        assert_eq!(
            target
                .get_local_store()
                .get_changelog_since_version(ZERO_REGISTRY_VERSION)
                .unwrap(),
            source
                .get_local_store()
                .get_changelog_since_version(ZERO_REGISTRY_VERSION)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_start_polling_twice_fails() {
        let replicator = new_locally_initialized_replicator(INIT_NUM_VERSIONS).await;
        let token = CancellationToken::new();

        assert!(!replicator.started.load(Ordering::Relaxed));

        let fut = replicator.start_polling(token.clone());
        assert!(fut.is_ok());
        assert!(replicator.started.load(Ordering::Relaxed));

        let fut = replicator.start_polling(token);
        assert!(fut.is_err_and(|e| e.kind() == ErrorKind::AlreadyExists));
        assert!(replicator.started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_stop_polling_idempotent() {
        let replicator = new_locally_initialized_replicator(INIT_NUM_VERSIONS).await;
        assert!(!replicator.cancelled.load(Ordering::Relaxed));
        replicator.stop_polling();
        assert!(replicator.cancelled.load(Ordering::Relaxed));
        replicator.stop_polling();
        assert!(replicator.cancelled.load(Ordering::Relaxed));
    }
}
