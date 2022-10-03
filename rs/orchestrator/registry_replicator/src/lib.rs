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

use crate::internal_state::InternalState;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_config::{registry_client::DataProviderConfig, Config};
use ic_crypto::CryptoComponentFatClient;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_interfaces_registry::{RegistryClient, RegistryDataProvider, ZERO_REGISTRY_VERSION};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::{Changelog, ChangelogEntry, KeyMutation, LocalStore, LocalStoreImpl};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{NodeId, RegistryVersion};
use metrics::RegistryreplicatorMetrics;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use url::Url;

pub mod args;
mod internal_state;
pub mod metrics;

pub struct RegistryReplicator {
    logger: ReplicaLogger,
    node_id: Option<NodeId>,
    registry_client: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    poll_delay: Duration,
    metrics: Arc<RegistryreplicatorMetrics>,
}

impl RegistryReplicator {
    pub fn new_from_config(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        config: &Config,
    ) -> Self {
        // We only support the local store data provider
        let DataProviderConfig::LocalStore(local_store_path) = config
            .registry_client
            .data_provider
            .clone()
            .expect("registry data provider is not configured");

        let local_store = Arc::new(LocalStoreImpl::new(local_store_path.clone()));
        std::fs::create_dir_all(local_store_path)
            .expect("Could not create directory for registry local store.");

        let poll_delay =
            std::time::Duration::from_millis(config.nns_registry_replicator.poll_delay_duration_ms);

        // Initialize registry client and start polling/caching *local* store for
        // updates
        let registry_client = Self::initialize_registry_client(local_store.clone());

        let metrics = Arc::new(RegistryreplicatorMetrics::new(&MetricsRegistry::global()));

        Self {
            logger,
            node_id,
            registry_client,
            local_store,
            started: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            poll_delay,
            metrics,
        }
    }

    pub fn new_with_metrics_runtime(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        config: &Config,
        metrics_addr: SocketAddr,
    ) -> (Self, MetricsRuntimeImpl) {
        let replicator = RegistryReplicator::new_from_config(logger.clone(), node_id, config);
        let crypto =
            CryptoComponentFatClient::new_for_verification_only(replicator.get_registry_client());

        let metrics_config = MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
        };
        let _runtime = MetricsRuntimeImpl::new(
            tokio::runtime::Handle::current(),
            metrics_config,
            MetricsRegistry::global(),
            replicator.get_registry_client(),
            Arc::new(crypto),
            &logger.inner_logger.root,
        );

        (replicator, _runtime)
    }

    /// initialize a new registry client and start polling the given data
    /// provider for registry updates
    fn initialize_registry_client(
        data_provider: Arc<dyn RegistryDataProvider>,
    ) -> Arc<dyn RegistryClient> {
        let metrics_registry = MetricsRegistry::global();
        let registry_client = Arc::new(RegistryClientImpl::new(
            data_provider,
            Some(&metrics_registry),
        ));

        if let Err(e) = registry_client.fetch_and_start_polling() {
            panic!("fetch_and_start_polling failed: {}", e);
        };

        registry_client
    }

    /// Return NNS [`Url`]s and [`ThresholdSigPublicKey`] if configured
    pub fn parse_registry_access_info_from_config(
        &self,
        config: &Config,
    ) -> (Vec<Url>, Option<ThresholdSigPublicKey>) {
        let nns_urls = match config.registration.nns_url.clone() {
            None => {
                info!(self.logger, "No NNS Url is configured.");
                vec![]
            }
            Some(string) => string
                .split(',')
                .flat_map(|s| match Url::parse(s) {
                    Err(_) => {
                        info!(
                            self.logger,
                            "Could not parse registration NNS url from config."
                        );
                        None
                    }
                    Ok(url) => Some(url),
                })
                .collect::<Vec<Url>>(),
        };

        let nns_pub_key = match config.registration.nns_pub_key_pem.clone() {
            None => {
                info!(self.logger, "No NNS public key is configured.");
                None
            }
            Some(path) => match parse_threshold_sig_key(&path) {
                Err(e) => {
                    info!(
                        self.logger,
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
        &self,
        nns_urls: Vec<Url>,
        nns_pub_key: Option<ThresholdSigPublicKey>,
    ) {
        // If the local registry store is not empty, exit.
        if !self
            .local_store
            .get_changelog_since_version(ZERO_REGISTRY_VERSION)
            .expect("Could not read registry local store.")
            .is_empty()
        {
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
            // Note, code duplicate in internal_state.rs poll()
            match registry_canister
                .get_certified_changes_since(registry_version.get(), &nns_pub_key)
                .await
            {
                Ok((mut records, _, t)) => {
                    // We fetched the latest version.
                    if records.is_empty() {
                        return;
                    }
                    records.sort_by_key(|tr| tr.version);
                    let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
                        let rel_version = (r.version - registry_version).get();
                        if cl.len() < rel_version as usize {
                            cl.push(ChangelogEntry::default());
                        }
                        cl.last_mut().unwrap().push(KeyMutation {
                            key: r.key.clone(),
                            value: r.value.clone(),
                        });
                        cl
                    });

                    let entries = changelog.len();

                    changelog
                        .into_iter()
                        .enumerate()
                        .try_for_each(|(i, cle)| {
                            let v = registry_version + RegistryVersion::from(i as u64 + 1);
                            self.local_store.store(v, cle)
                        })
                        .expect("Could not write to local store.");
                    self.local_store
                        .update_certified_time(t.as_nanos_since_unix_epoch())
                        .expect("Could not store certified time");
                    registry_version += RegistryVersion::from(entries as u64);
                    timeout = 1;
                }
                Err(e) => {
                    warn!(
                        self.logger,
                        "Couldn't fetch registry updates (retry in {}s): {:?}", timeout, e
                    );
                    tokio::time::sleep(Duration::from_secs(timeout)).await;
                    timeout *= 2;
                    timeout = timeout.min(60); // limit the timeout by a minute max
                }
            }
        }
    }

    /// Calls [`Self::poll()`] asynchronously and spawns a background task that
    /// continuously polls for updates.
    /// The background task is stopped when the object is dropped.
    pub async fn start_polling(
        &self,
        nns_urls: Vec<Url>,
        nns_pub_key: Option<ThresholdSigPublicKey>,
    ) -> Result<JoinHandle<()>, Error> {
        if self.started.swap(true, Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "'start_polling' was already called",
            ));
        }

        // Initialize the registry local store. Will not return if the nns is not
        // reachable.
        self.initialize_local_store(nns_urls, nns_pub_key).await;

        let mut internal_state = InternalState::new(
            self.logger.clone(),
            self.node_id,
            self.registry_client.clone(),
            self.local_store.clone(),
            self.poll_delay,
        );

        let logger = self.logger.clone();
        let metrics = self.metrics.clone();
        let registry_client = self.registry_client.clone();
        let cancelled = Arc::clone(&self.cancelled);
        let poll_delay = self.poll_delay;
        let handle = tokio::spawn(async move {
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
                metrics
                    .registry_version
                    .set(registry_client.get_latest_version().get() as i64);
                tokio::time::sleep(poll_delay).await;
            }
        });
        Ok(handle)
    }

    /// Set the local registry data to what is contained in the provided local
    /// store.
    fn set_local_registry_data(&self, source_registry: &dyn LocalStore) {
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

    pub fn stop_polling_and_set_local_registry_data(&self, source_registry: &dyn LocalStore) {
        self.stop_polling();
        self.set_local_registry_data(source_registry);
    }

    pub fn stop_polling(&self) {
        self.cancelled.fetch_or(true, Ordering::Relaxed);
    }

    pub fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        self.registry_client.clone()
    }

    pub fn get_local_store(&self) -> Arc<dyn LocalStore> {
        self.local_store.clone()
    }
}

impl Drop for RegistryReplicator {
    fn drop(&mut self) {
        self.stop_polling();
    }
}
