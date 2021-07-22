#![deny(missing_docs)]
//! The ingress manager crate implements the selection and validation of
//! ingresses on the internet computer block chain.

mod ingress_handler;
mod ingress_selector;

use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache, crypto::IngressSigVerifier,
    execution_environment::IngressHistoryReader, registry::RegistryClient,
    state_manager::StateManager,
};
use ic_logger::{error, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_registry_client::helper::subnet::{IngressMessageSettings, SubnetRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::IngressMessageId,
    malicious_flags::MaliciousFlags,
    time::{Time, UNIX_EPOCH},
    RegistryVersion, SubnetId,
};
use prometheus::Histogram;
use std::sync::{Arc, RwLock};

/// Keeps the metrics to be exported by the IngressManager
struct IngressManagerMetrics {
    ingress_handler_time: Histogram,
    ingress_selector_get_payload_time: Histogram,
    ingress_selector_validate_payload_time: Histogram,
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
                "Ingress Selector vaidate_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
        }
    }
}

/// This struct is responsible for ingresses. It validates, invalidates,
/// advertizes, purges ingresses, and selects the ingresses to be included in
/// the blocks.
pub struct IngressManager {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ingress_hist_reader: Box<dyn IngressHistoryReader>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_signature_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    metrics: IngressManagerMetrics,
    subnet_id: SubnetId,
    log: ReplicaLogger,
    messages_to_purge: RwLock<Vec<Vec<IngressMessageId>>>,

    /// Remember last purge time to control purge frequency.
    pub(crate) last_purge_time: std::sync::RwLock<Time>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    malicious_flags: MaliciousFlags,
}

impl IngressManager {
    #[allow(clippy::too_many_arguments)]
    /// Constructs an IngressManager
    pub fn new(
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        ingress_hist_reader: Box<dyn IngressHistoryReader>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_signature_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
        metrics_registry: MetricsRegistry,
        subnet_id: SubnetId,
        log: ReplicaLogger,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            consensus_pool_cache,
            ingress_hist_reader,
            registry_client,
            ingress_signature_crypto,
            metrics: IngressManagerMetrics::new(metrics_registry),
            subnet_id,
            log,
            last_purge_time: std::sync::RwLock::new(UNIX_EPOCH),
            messages_to_purge: RwLock::new(Vec::new()),
            state_manager,
            cycles_account_manager,
            malicious_flags,
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
            Ok(settings) => settings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_artifact_pool::ingress_pool::IngressPoolImpl;
    use ic_interfaces::registry::RegistryClient;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client::client::RegistryClientImpl;
    use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
    use ic_registry_keys::make_subnet_record_key;
    use ic_test_utilities::{
        artifact_pool_config::with_test_pool_config,
        consensus::MockConsensusCache,
        crypto::temp_crypto_component_with_fake_registry,
        cycles_account_manager::CyclesAccountManagerBuilder,
        history::MockIngressHistory,
        registry::test_subnet_record,
        state::ReplicatedStateBuilder,
        state_manager::MockStateManager,
        types::ids::{node_test_id, subnet_test_id},
        with_test_replica_logger,
    };
    use ic_types::{ingress::IngressStatus, Height, RegistryVersion, SubnetId};
    use std::sync::Arc;

    pub(crate) fn setup_registry(
        subnet_id: SubnetId,
        ingress_bytes_per_block_soft_cap: usize,
        max_ingress_bytes_per_message: usize,
    ) -> Arc<dyn RegistryClient> {
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let mut subnet_record = test_subnet_record();
        subnet_record.ingress_bytes_per_block_soft_cap = ingress_bytes_per_block_soft_cap as u64;
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
        consensus_pool_cache: Option<Arc<dyn ConsensusPoolCache>>,
        state: Option<ReplicatedState>,
        run: impl FnOnce(IngressManager, IngressPoolImpl),
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
            (
                setup_registry(subnet_id, 1024 * 1024, 60 * 1024 * 1024),
                subnet_id,
            )
        });
        let consensus_pool_cache =
            consensus_pool_cache.unwrap_or_else(|| Arc::new(MockConsensusCache::new()));

        let mut state_manager = MockStateManager::new();
        state_manager.expect_get_state_at().return_const(Ok(
            ic_interfaces::state_manager::Labeled::new(
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
                run(
                    IngressManager::new(
                        consensus_pool_cache,
                        ingress_hist_reader,
                        registry,
                        ingress_signature_crypto,
                        metrics_registry.clone(),
                        subnet_id,
                        log.clone(),
                        Arc::new(state_manager),
                        cycles_account_manager,
                        MaliciousFlags::default(),
                    ),
                    IngressPoolImpl::new(pool_config, metrics_registry, log),
                )
            })
        })
    }

    pub(crate) fn setup(run: impl FnOnce(IngressManager, IngressPoolImpl)) {
        setup_with_params(None, None, None, None, run)
    }
}
