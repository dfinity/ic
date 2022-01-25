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
use ic_config::{registry_client::DataProviderConfig, Config};
use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use ic_interfaces::registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::{create_data_provider, RegistryClientImpl};
use ic_registry_common::local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStore, LocalStoreImpl,
};
use ic_registry_common::registry::RegistryCanister;
use ic_types::{NodeId, RegistryVersion};
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

mod internal_state;

pub struct RegistryReplicator {
    logger: ReplicaLogger,
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    poll_delay: Duration,
}

impl RegistryReplicator {
    pub fn new(logger: ReplicaLogger, config: &Config, node_id: NodeId) -> Self {
        let registry_client = Self::initialize_registry_client(config);

        // we only support the local store data provider
        let local_store_path = if let DataProviderConfig::LocalStore(path) = config
            .registry_client
            .data_provider
            .clone()
            .expect("registry data provider is not configured")
        {
            path
        } else {
            panic!("Only LocalStore is supported in the orchestrator.");
        };

        let local_store = Arc::new(LocalStoreImpl::new(local_store_path));

        Self {
            logger,
            node_id,
            registry_client,
            local_store,
            started: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            poll_delay: std::time::Duration::from_millis(
                config.nns_registry_replicator.poll_delay_duration_ms,
            ),
        }
    }

    fn initialize_registry_client(config: &Config) -> Arc<dyn RegistryClient> {
        let metrics_registry = MetricsRegistry::global();
        let data_provider = create_data_provider(
            config
                .registry_client
                .data_provider
                .as_ref()
                .expect("No data provider was provided in the registry client configuration"),
            // We set the NNS public key to `None` (and thus disable registry data signature
            // verification). See the Rustdoc of `RegistryHelper` for an explanation.
            None,
        );
        let registry_client = Arc::new(RegistryClientImpl::new(
            data_provider,
            Some(&metrics_registry),
        ));

        if let Err(e) = registry_client.fetch_and_start_polling() {
            panic!("fetch_and_start_polling failed: {}", e);
        };

        registry_client
    }

    async fn initialize_local_store(&self, node_config: &Config) {
        let local_store_path = if let DataProviderConfig::LocalStore(p) = node_config
            .registry_client
            .data_provider
            .clone()
            .expect("Data Provider is not configured.")
        {
            p
        } else {
            panic!("LocalStore is the only data registry provider supported.")
        };
        std::fs::create_dir_all(local_store_path)
            .expect("Could not create directory for registry local store.");
        if self
            .local_store
            .get_changelog_since_version(ZERO_REGISTRY_VERSION)
            .expect("Could not read registry local store.")
            .is_empty()
        {
            let nns_urls = node_config
                .registration
                .nns_url
                .clone()
                .expect("Registry Local Store is empty and no NNS Url configured.")
                .split(',')
                .map(|s| Url::parse(s).expect("Could not parse registration NNS url from config"))
                .collect::<Vec<Url>>();

            let nns_pub_key_path = node_config
                .registration
                .nns_pub_key_pem
                .clone()
                .expect("Registry Local Store is empty and no NNS Public Key configured.");

            let nns_pub_key = parse_threshold_sig_key(&nns_pub_key_path)
                .expect("Could not parse configured NNS Public Key file.");

            let registry_canister = RegistryCanister::new(nns_urls);
            while self
                .local_store
                .get_changelog_since_version(ZERO_REGISTRY_VERSION)
                .expect("Could not read registry local store.")
                .is_empty()
            {
                match registry_canister
                    .get_certified_changes_since(0, &nns_pub_key)
                    .await
                {
                    Ok((mut records, _, t)) if !records.is_empty() => {
                        records.sort_by_key(|tr| tr.version);
                        let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
                            let rel_version = (r.version - ZERO_REGISTRY_VERSION).get();
                            if cl.len() < rel_version as usize {
                                cl.push(ChangelogEntry::default());
                            }
                            cl.last_mut().unwrap().push(KeyMutation {
                                key: r.key.clone(),
                                value: r.value.clone(),
                            });
                            cl
                        });

                        changelog
                            .into_iter()
                            .enumerate()
                            .try_for_each(|(i, cle)| {
                                let v = ZERO_REGISTRY_VERSION + RegistryVersion::from(i as u64 + 1);
                                self.local_store.store(v, cle)
                            })
                            .expect("Could not write to local store.");
                        self.local_store
                            .update_certified_time(t.as_nanos_since_unix_epoch())
                            .expect("Could not store certified time");
                        return;
                    }
                    Err(e) => warn!(
                        self.logger,
                        "Could not fetch registry changelog from NNS: {:?}", e
                    ),
                    _ => {}
                };
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    /// Calls `poll()` asynchronously and spawns a background task that
    /// continuously polls for updates. Returns the result of the first poll.
    /// The background task is stopped when the object is dropped.
    pub async fn fetch_and_start_polling(&self, config: &Config) -> Result<(), Error> {
        if self.started.swap(true, Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "'start_polling' was already called",
            ));
        }

        // Initialize the registry local store. Will not return if the nns is not
        // reachable.
        self.initialize_local_store(config).await;

        let mut internal_state = InternalState::new(
            self.logger.clone(),
            self.node_id,
            self.registry_client.clone(),
            self.local_store.clone(),
            self.poll_delay,
        );
        let res = internal_state
            .poll()
            .map_err(|err| Error::new(ErrorKind::Other, err));

        let logger = self.logger.clone();
        let cancelled = Arc::clone(&self.cancelled);
        let poll_delay = self.poll_delay;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_delay);
            while !cancelled.load(Ordering::Relaxed) {
                let tick_time = interval.tick().await;
                // The relevant I/O-operation of the poll() function is querying
                // a node on the NNS for updates. As we set the query timeout to
                // `poll_delay` when constructing the underlying
                // `RegistryCanister` abstraction, we are guaranteed that
                // `poll()` returns after a maximal duration of `poll_delay`.
                if let Err(msg) = internal_state.poll() {
                    warn!(logger, "Polling the NNS registry failed: {}", msg);
                } else {
                    debug!(logger, "Polling the NNS succeeded.");
                }

                // Ticks happen at _absolute_ points in time. Thus, if the
                // delay between ticks (because, for example, under load the
                // scheduler cannot schedule this thread) is _longer_ than the
                // interval length, the intervals "pile up" and tick() will
                // immediately return a number of times.
                //
                // To prevent a situation where nodes start flooding the NNS
                // with requests, we simply reset the interval if the "skew"
                // becomes larger than poll_delay (or 2*poll_delay, accounting
                // for the maximum delay of poll() after the tick_time).
                if tokio::time::Instant::now().duration_since(tick_time) > 2 * poll_delay {
                    interval = tokio::time::interval(poll_delay);
                }
            }
        });
        res
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
