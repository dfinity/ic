#![deny(missing_docs)]
//! The ingress manager crate implements the selection and validation of
//! ingresses on the internet computer block chain.

mod ingress_handler;
mod ingress_selector;

#[cfg(test)]
mod proptests;

use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::{
    consensus_pool::ConsensusTime, execution_environment::IngressHistoryReader,
    ingress_pool::IngressPool, time_source::TimeSource,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{error, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_registry_client_helpers::crypto::root_of_trust::RegistryRootOfTrustProvider;
use ic_registry_client_helpers::subnet::{IngressMessageSettings, SubnetRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::{HttpRequest, HttpRequestContent, SignedIngressContent};
use ic_types::{
    artifact::IngressMessageId,
    consensus::BlockPayload,
    crypto::CryptoHashOf,
    malicious_flags::MaliciousFlags,
    time::{Time, UNIX_EPOCH},
    Height, RegistryVersion, SubnetId,
};
use ic_validator::{
    CanisterIdSet, HttpRequestVerifier, HttpRequestVerifierImpl, RequestValidationError,
};
use prometheus::{Histogram, IntGauge};
use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, RwLock},
};

/// Cache of sets of message ids for past payloads. The index used here is a
/// tuple (Height, HashOfBatchPayload) for two reasons:
/// 1. We want to purge this cache by height, for those below certified height.
/// 2. There could be more than one payloads at a given height due to blockchain
///    branching.
type IngressPayloadCache =
    BTreeMap<(Height, CryptoHashOf<BlockPayload>), Arc<HashSet<IngressMessageId>>>;

/// Keeps the metrics to be exported by the IngressManager
struct IngressManagerMetrics {
    ingress_handler_time: Histogram,
    ingress_selector_get_payload_time: Histogram,
    ingress_selector_validate_payload_time: Histogram,
    ingress_payload_cache_size: IntGauge,
}

impl IngressManagerMetrics {
    fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            ingress_handler_time: metrics_registry.histogram(
                "ingress_handler_execution_time",
                "Ingress Handler execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_get_payload_time: metrics_registry.histogram(
                "ingress_selector_get_payload_time",
                "Ingress Selector get_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_validate_payload_time: metrics_registry.histogram(
                "ingress_selector_validate_payload_time",
                "Ingress Selector validate_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_payload_cache_size: metrics_registry.int_gauge(
                "ingress_payload_cache_size",
                "The number of HashSets in payload builder's ingress payload cache.",
            ),
        }
    }
}

/// The kind of RandomState you want to generate.
pub enum RandomStateKind {
    /// Creates random states using the default [`std::collections::hash_map::RandomState`].
    Random,
    /// Creates a deterministic default random state. Use it for testing purposes,
    /// to create a repeatable element order.
    Deterministic,
}

impl RandomStateKind {
    /// Creates a custom random state of the given kind, which can be used
    /// to seed data structures like hashmaps.
    fn create_state(&self) -> CustomRandomState {
        match self {
            Self::Random => CustomRandomState::Random(RandomState::new()),
            Self::Deterministic => CustomRandomState::Deterministic,
        }
    }
}

/// A custom RandomState we can use to control the randomness of a hashmap.
#[derive(Clone)]
enum CustomRandomState {
    Random(RandomState),
    Deterministic,
}

impl BuildHasher for CustomRandomState {
    type Hasher = DefaultHasher;

    fn build_hasher(&self) -> DefaultHasher {
        match self {
            Self::Deterministic => DefaultHasher::new(),
            Self::Random(r) => r.build_hasher(),
        }
    }
}

/// This struct is responsible for ingresses. It validates, invalidates,
/// advertizes, purges ingresses, and selects the ingresses to be included in
/// the blocks.
pub struct IngressManager {
    time_source: Arc<dyn TimeSource>,
    consensus_time: Arc<dyn ConsensusTime>,
    ingress_hist_reader: Box<dyn IngressHistoryReader>,
    ingress_payload_cache: Arc<RwLock<IngressPayloadCache>>,
    ingress_pool: Arc<RwLock<dyn IngressPool>>,
    registry_client: Arc<dyn RegistryClient>,
    request_validator:
        Arc<dyn HttpRequestVerifier<SignedIngressContent, RegistryRootOfTrustProvider>>,
    metrics: IngressManagerMetrics,
    subnet_id: SubnetId,
    log: ReplicaLogger,
    messages_to_purge: RwLock<Vec<Vec<IngressMessageId>>>,

    /// Remember last purge time to control purge frequency.
    pub(crate) last_purge_time: RwLock<Time>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    cycles_account_manager: Arc<CyclesAccountManager>,

    /// A determinism flag for testing. Used for making hashmaps in the ingress selector
    /// deterministic. Set to `RandomStateKind::Random` in production.
    random_state: RandomStateKind,
}

impl IngressManager {
    #[allow(clippy::too_many_arguments)]
    /// Constructs an IngressManager
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        consensus_time: Arc<dyn ConsensusTime>,
        ingress_hist_reader: Box<dyn IngressHistoryReader>,
        ingress_pool: Arc<RwLock<dyn IngressPool>>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_signature_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
        metrics_registry: MetricsRegistry,
        subnet_id: SubnetId,
        log: ReplicaLogger,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        malicious_flags: MaliciousFlags,
        random_state: RandomStateKind,
    ) -> Self {
        let request_validator = if malicious_flags.maliciously_disable_ingress_validation {
            pub struct DisabledHttpRequestVerifier;

            impl<C: HttpRequestContent, R> HttpRequestVerifier<C, R> for DisabledHttpRequestVerifier {
                fn validate_request(
                    &self,
                    _request: &HttpRequest<C>,
                    _current_time: Time,
                    _root_of_trust_provider: &R,
                ) -> Result<CanisterIdSet, RequestValidationError> {
                    Ok(CanisterIdSet::all())
                }
            }

            Arc::new(DisabledHttpRequestVerifier) as Arc<_>
        } else {
            Arc::new(HttpRequestVerifierImpl::new(ingress_signature_crypto)) as Arc<_>
        };
        Self {
            time_source,
            consensus_time,
            ingress_hist_reader,
            ingress_payload_cache: Arc::new(RwLock::new(BTreeMap::new())),
            ingress_pool,
            registry_client,
            request_validator,
            metrics: IngressManagerMetrics::new(metrics_registry),
            subnet_id,
            log,
            last_purge_time: RwLock::new(UNIX_EPOCH),
            messages_to_purge: RwLock::new(Vec::new()),
            state_reader,
            cycles_account_manager,
            random_state,
        }
    }

    fn get_ingress_message_settings(
        &self,
        registry_version: RegistryVersion,
    ) -> Option<IngressMessageSettings> {
        match self
            .registry_client
            .get_ingress_message_settings(self.subnet_id, registry_version)
        {
            Ok(None) => {
                error!(
                    self.log,
                    "No subnet record found for registry version={:?} and subnet_id={:?}",
                    registry_version,
                    self.subnet_id,
                );
                None
            }
            Err(err) => {
                error!(
                    self.log,
                    "Could not retrieve ingress message param max_ingress_bytes_per_message: {:?}",
                    err
                );
                None
            }
            Ok(settings) => settings.map(|mut settings| {
                // Make sure that we always allow a single message per block
                if settings.max_ingress_messages_per_block == 0 {
                    warn!(
                        every_n_seconds => 300,
                        self.log,
                        "max_ingress_messages_per_block configured incorrectly (set to 0, should be set to at least 1)"
                    );
                    settings.max_ingress_messages_per_block = 1;
                }
                settings
            }),
        }
    }

    fn registry_root_of_trust_provider(
        &self,
        registry_version: RegistryVersion,
    ) -> RegistryRootOfTrustProvider {
        RegistryRootOfTrustProvider::new(Arc::clone(&self.registry_client), registry_version)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ic_artifact_pool::ingress_pool::IngressPoolImpl;
    use ic_interfaces_mocks::consensus_pool::MockConsensusTime;
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client::client::RegistryClientImpl;
    use ic_registry_keys::make_subnet_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities::{
        artifact_pool_config::with_test_pool_config,
        crypto::temp_crypto_component_with_fake_registry,
        cycles_account_manager::CyclesAccountManagerBuilder,
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::test_subnet_record;
    use ic_test_utilities_state::{MockIngressHistory, ReplicatedStateBuilder};
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{ingress::IngressStatus, Height, RegistryVersion, SubnetId};
    use std::{ops::DerefMut, sync::Arc};

    pub(crate) fn setup_registry(
        subnet_id: SubnetId,
        max_ingress_bytes_per_message: usize,
    ) -> Arc<dyn RegistryClient> {
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let mut subnet_record = test_subnet_record();
        subnet_record.max_ingress_bytes_per_message = max_ingress_bytes_per_message as u64;

        registry_data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                RegistryVersion::from(1),
                Some(subnet_record),
            )
            .expect("Failed to add subnet record.");
        let registry = Arc::new(RegistryClientImpl::new(
            Arc::clone(&registry_data_provider) as Arc<_>,
            None,
        ));
        registry.fetch_and_start_polling().unwrap();
        registry
    }

    pub(crate) fn setup_with_params(
        ingress_hist_reader: Option<Box<dyn IngressHistoryReader>>,
        registry_and_subnet_id: Option<(Arc<dyn RegistryClient>, SubnetId)>,
        consensus_time: Option<Arc<dyn ConsensusTime>>,
        state: Option<ReplicatedState>,
        run: impl FnOnce(IngressManager, Arc<RwLock<IngressPoolImpl>>),
    ) {
        let ingress_hist_reader = ingress_hist_reader.unwrap_or_else(|| {
            let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
            ingress_hist_reader
                .expect_get_status_at_height()
                .returning(|_| Ok(Box::new(|_| IngressStatus::Unknown)));
            ingress_hist_reader
        });
        let (registry, subnet_id) = registry_and_subnet_id.unwrap_or_else(|| {
            let subnet_id = subnet_test_id(0);
            (setup_registry(subnet_id, 60 * 1024 * 1024), subnet_id)
        });
        let consensus_time = consensus_time.unwrap_or_else(|| Arc::new(MockConsensusTime::new()));

        let mut state_manager = MockStateManager::new();
        state_manager.expect_get_state_at().return_const(Ok(
            ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(state.unwrap_or_else(|| ReplicatedStateBuilder::default().build())),
            ),
        ));
        with_test_replica_logger(|log| {
            with_test_pool_config(|pool_config| {
                let metrics_registry = MetricsRegistry::new();
                const VALIDATOR_NODE_ID: u64 = 42;
                let ingress_signature_crypto = Arc::new(temp_crypto_component_with_fake_registry(
                    node_test_id(VALIDATOR_NODE_ID),
                ));
                let cycles_account_manager = Arc::new(
                    CyclesAccountManagerBuilder::new()
                        .with_subnet_id(subnet_id)
                        .build(),
                );
                let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
                    node_test_id(VALIDATOR_NODE_ID),
                    pool_config,
                    metrics_registry.clone(),
                    log.clone(),
                )));
                let time_source = FastForwardTimeSource::new();
                time_source.set_time(UNIX_EPOCH).unwrap();
                run(
                    IngressManager::new(
                        time_source,
                        consensus_time,
                        ingress_hist_reader,
                        ingress_pool.clone(),
                        registry,
                        ingress_signature_crypto,
                        metrics_registry,
                        subnet_id,
                        log,
                        Arc::new(state_manager),
                        cycles_account_manager,
                        MaliciousFlags::default(),
                        RandomStateKind::Random,
                    ),
                    ingress_pool,
                )
            })
        })
    }

    pub(crate) fn setup(run: impl FnOnce(IngressManager, Arc<RwLock<IngressPoolImpl>>)) {
        setup_with_params(None, None, None, None, run)
    }

    /// This function takes a lock on the ingress pool and allows the closure to access it.
    pub(crate) fn access_ingress_pool<F, T>(ingress_pool: &Arc<RwLock<IngressPoolImpl>>, f: F) -> T
    where
        F: FnOnce(&mut IngressPoolImpl) -> T,
    {
        f(ingress_pool.write().unwrap().deref_mut())
    }
}
