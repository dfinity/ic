//! Keeps track of the `ic-gateway` configuration of a cloud engine node.
//!
//! Cloud engine subnets are self-contained: each one has an `engine-operator`
//! canister on the subnet itself that holds all the relevant configuration.
//! This module polls that canister and hands the result to whoever runs
//! `ic-gateway`.

mod agent;
pub(crate) mod config;
mod discovery;
mod error;
#[cfg(test)]
mod integration_tests;
mod operator;

use crate::{
    metrics::OrchestratorMetrics, orchestrator::SubnetAssignment,
    registration::NodeRegistrationCrypto, registry_helper::RegistryHelper,
};
use config::{EngineConfig, validate_engine_config};
use discovery::Discovery;
use error::{CloudEngineError, CloudEngineResult};
use ic_agent::Agent;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{CanisterId, RegistryVersion, SubnetId, time::current_time};
use operator::OperatorClient;
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use url::Url;

/// Value of the `outcome` label of `cloud_engine_config_fetches`.
const OUTCOME_OK: &str = "ok";
const OUTCOME_INCOMPLETE: &str = "incomplete";
const OUTCOME_NOT_READY: &str = "not_ready";
const OUTCOME_ERROR: &str = "error";

/// How many consecutive [`CloudEngineError::NotReady`] answers to tolerate
/// before resolving the operator again. At one check every 10 seconds this is
/// about 5 minutes.
const MAX_CONSECUTIVE_NOT_READY: u32 = 30;

pub(crate) struct CloudEngineManager {
    registry: Arc<RegistryHelper>,
    /// Which subnet this node serves, as the upgrade loop determined it.
    subnet_assignment: Arc<RwLock<SubnetAssignment>>,
    /// Signs as this node, which is how the operator canister recognizes it.
    operator_agent: Agent,
    discovery: Discovery,
    /// The last configuration that passed validation, shared with the process
    /// manager that runs `ic-gateway`. Only ever replaced by another valid one,
    /// never cleared.
    current_config: Arc<RwLock<Option<EngineConfig>>>,
    consecutive_not_ready: u32,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl CloudEngineManager {
    /// `None` when this node cannot read an engine configuration at all: no
    /// engine management canister to find the operator through, or no agent to
    /// reach it with.
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        subnet_assignment: Arc<RwLock<SubnetAssignment>>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        engine_management_canister_id: Option<CanisterId>,
        replica_listen_addr: SocketAddr,
        current_config: Arc<RwLock<Option<EngineConfig>>>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Option<Self> {
        let engine_management_canister_id = engine_management_canister_id?;

        // The replica listens on a wildcard address, so only its port is of use
        // here: the operator canister is on this node's own subnet.
        let replica_url = Url::parse(&format!("http://127.0.0.1:{}", replica_listen_addr.port()))
            .inspect_err(|err| warn!(logger, "Cannot address the local replica: {err}"))
            .ok()?;
        let operator_agent =
            agent::node_signed(registry.get_registry_client(), crypto, replica_url, &logger)
                .inspect_err(|err| {
                    warn!(
                        logger,
                        "Cannot build the agent to the engine operator: {err}"
                    )
                })
                .ok()?;

        let discovery = Discovery::new(
            Arc::clone(&registry),
            engine_management_canister_id,
            logger.clone(),
        );

        Some(Self {
            registry,
            subnet_assignment,
            operator_agent,
            discovery,
            current_config,
            consecutive_not_ready: 0,
            metrics,
            logger,
        })
    }

    /// Refreshes the engine configuration, keeping the previous one on failure.
    pub(crate) async fn check(&mut self) {
        let subnet_id = match *self.subnet_assignment.read().unwrap() {
            SubnetAssignment::Assigned(subnet_id) => subnet_id,
            // The upgrade loop determines the assignment on its first run.
            SubnetAssignment::Unassigned | SubnetAssignment::Unknown => return,
        };
        let version = self.registry.get_latest_version();

        match self.registry.is_cloud_engine_subnet(subnet_id, version) {
            Ok(true) => {}
            // Only all-in-one nodes have an engine operator to ask.
            Ok(false) => return,
            // Whether this node is an engine is still unknown, so this says
            // nothing about the operator and must not touch it.
            Err(err) => {
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_ERROR])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger, "Could not determine the type of subnet {}: {}", subnet_id, err
                );
                return;
            }
        }

        let outcome = self.fetch(subnet_id, version).await;
        self.apply(outcome);
    }

    /// Records what a fetch produced: publishes a new configuration, and
    /// discards the resolved operator once it stops answering usefully.
    fn apply(&mut self, outcome: CloudEngineResult<EngineConfig>) {
        self.metrics
            .cloud_engine_config_fetches
            .with_label_values(&[outcome_label(&outcome)])
            .inc();
        // Only *consecutive* unrecognized answers spend the budget below.
        if !matches!(outcome, Err(CloudEngineError::NotReady)) {
            self.consecutive_not_ready = 0;
        }

        match outcome {
            Ok(new_config) => {
                self.metrics
                    .cloud_engine_config_last_success
                    .set(current_time().as_secs_since_unix_epoch() as i64);

                let mut current_config = self.current_config.write().unwrap();
                if current_config.as_ref() != Some(&new_config) {
                    info!(self.logger, "New engine configuration: {:?}", new_config);
                    *current_config = Some(new_config);
                }
            }
            Err(CloudEngineError::Incomplete(field)) => warn!(
                every_n_seconds => 60,
                self.logger, "The engine is not fully configured yet: {} is not set", field
            ),
            Err(CloudEngineError::NotReady) => {
                warn!(
                    every_n_seconds => 60,
                    self.logger, "The engine operator does not recognize this node yet; retrying"
                );

                self.consecutive_not_ready += 1;
                if self.consecutive_not_ready >= MAX_CONSECUTIVE_NOT_READY {
                    warn!(
                        self.logger,
                        "The engine operator has not recognized this node for {} \
                        consecutive attempts; re-resolving the operator",
                        self.consecutive_not_ready
                    );
                    self.discovery.invalidate();
                    self.consecutive_not_ready = 0;
                }
            }
            Err(CloudEngineError::Failed(err)) => {
                warn!(
                    every_n_seconds => 60,
                    self.logger, "Could not read the engine configuration: {}", err
                );
                // Anything but "not ready" suggests we resolved the wrong
                // canister, so look the operator up again next time.
                self.discovery.invalidate();
            }
        }
    }

    async fn fetch(
        &mut self,
        own_subnet: SubnetId,
        version: RegistryVersion,
    ) -> CloudEngineResult<EngineConfig> {
        let operator_id = self.discovery.resolve(own_subnet, version).await?;
        let operator = OperatorClient::new(&self.operator_agent, operator_id);

        let http_gateway_config = operator.http_gateway_config().await?;
        let acme_credentials = operator.acme_credentials().await?;

        validate_engine_config(http_gateway_config, acme_credentials)
    }
}

/// Metrics: the `outcome` label to count this result under.
fn outcome_label(outcome: &CloudEngineResult<EngineConfig>) -> &'static str {
    match outcome {
        Ok(_) => OUTCOME_OK,
        Err(CloudEngineError::Incomplete(_)) => OUTCOME_INCOMPLETE,
        Err(CloudEngineError::NotReady) => OUTCOME_NOT_READY,
        Err(CloudEngineError::Failed(_)) => OUTCOME_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
    use ic_interfaces_registry::RegistryClient;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::NODE_1;

    /// The operator this node has resolved before the outcome under test.
    fn operator() -> CanisterId {
        CanisterId::from_u64(3)
    }

    /// The configuration a successful fetch produces.
    fn config() -> EngineConfig {
        EngineConfig::for_test("engine.example.com")
    }

    /// A manager that has already resolved [`operator`]. It never reaches the
    /// network: the tests drive [`CloudEngineManager::apply`] directly with the
    /// outcome a fetch would have produced.
    fn manager_for_test() -> CloudEngineManager {
        let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(
            ProtoRegistryDataProvider::new(),
        )));
        registry_client.update_to_latest_version();
        let registry = Arc::new(RegistryHelper::new(
            NODE_1,
            Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
            no_op_logger(),
        ));
        // The constructor signs as this node, so the keys have to be real.
        let crypto = Arc::new(
            TempCryptoComponent::builder()
                .with_registry(registry_client)
                .with_node_id(NODE_1)
                .with_keys(NodeKeysToGenerate::only_node_signing_key())
                .build(),
        );

        let mut manager = CloudEngineManager::new(
            registry,
            Arc::new(RwLock::new(SubnetAssignment::Unknown)),
            crypto,
            Some(CanisterId::from_u64(1000)),
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            Arc::new(RwLock::new(None)),
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        )
        .expect("the manager should be constructible");
        manager.discovery.remember(operator());

        manager
    }

    /// How often the given outcome was recorded.
    fn fetches(manager: &CloudEngineManager, outcome: &str) -> u64 {
        manager
            .metrics
            .cloud_engine_config_fetches
            .with_label_values(&[outcome])
            .get()
    }

    #[test]
    fn a_new_configuration_is_published() {
        let mut manager = manager_for_test();

        manager.apply(Ok(config()));

        assert_eq!(*manager.current_config.read().unwrap(), Some(config()));
        assert_eq!(fetches(&manager, OUTCOME_OK), 1);
        // A configuration was served, so the operator stays resolved.
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }

    #[test]
    fn an_incomplete_configuration_keeps_the_previous_one() {
        let mut manager = manager_for_test();
        manager.apply(Ok(config()));

        manager.apply(Err(CloudEngineError::Incomplete("dns_api_urls")));

        // An engine that is being configured must not take `ic-gateway` down,
        // and it is the operator we expect, so it stays resolved.
        assert_eq!(*manager.current_config.read().unwrap(), Some(config()));
        assert_eq!(fetches(&manager, OUTCOME_INCOMPLETE), 1);
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }

    #[test]
    fn a_failure_keeps_the_configuration_but_re_resolves_the_operator() {
        let mut manager = manager_for_test();
        manager.apply(Ok(config()));

        manager.apply(Err(CloudEngineError::failed("the operator is on fire")));

        assert_eq!(*manager.current_config.read().unwrap(), Some(config()));
        assert_eq!(fetches(&manager, OUTCOME_ERROR), 1);
        assert_eq!(manager.discovery.remembered(), None);
    }

    #[test]
    fn not_ready_is_tolerated_until_the_budget_is_spent() {
        let mut manager = manager_for_test();

        for attempt in 1..MAX_CONSECUTIVE_NOT_READY {
            manager.apply(Err(CloudEngineError::NotReady));

            assert_eq!(
                manager.discovery.remembered(),
                Some(operator()),
                "the operator should survive attempt {attempt}"
            );
            assert_eq!(manager.consecutive_not_ready, attempt);
        }

        assert_eq!(manager.discovery.remembered(), Some(operator()));

        manager.apply(Err(CloudEngineError::NotReady));

        // An operator that never recognizes this node is likely not ours.
        assert_eq!(manager.discovery.remembered(), None);
        assert_eq!(manager.consecutive_not_ready, 0);
        assert_eq!(
            fetches(&manager, OUTCOME_NOT_READY),
            MAX_CONSECUTIVE_NOT_READY as u64
        );
    }

    #[test]
    fn any_other_outcome_restores_the_not_ready_budget() {
        let mut manager = manager_for_test();
        for _ in 1..MAX_CONSECUTIVE_NOT_READY {
            manager.apply(Err(CloudEngineError::NotReady));
        }

        manager.apply(Ok(config()));

        assert_eq!(manager.consecutive_not_ready, 0);

        // The next `NotReady` starts over, so the operator is kept.
        manager.apply(Err(CloudEngineError::NotReady));

        assert_eq!(manager.consecutive_not_ready, 1);
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }
}
