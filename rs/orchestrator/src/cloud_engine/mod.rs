//! Keeps track of the `ic-gateway` configuration of a cloud engine node.
//!
//! Cloud engine subnets are self-contained: each one has an `engine-operator`
//! canister on the subnet itself that holds the base domains the engine serves,
//! a DNS provider API for the ACME dns-01 challenge, and the ACME account to
//! renew certificates with. This module polls that canister and hands the result
//! to whoever runs `ic-gateway`.

mod agent;
pub(crate) mod config;
mod discovery;
mod error;
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
use std::sync::{Arc, RwLock};
use url::Url;

/// Value of the `outcome` label of `cloud_engine_config_fetches`.
const OUTCOME_OK: &str = "ok";
const OUTCOME_INCOMPLETE: &str = "incomplete";
const OUTCOME_NOT_READY: &str = "not_ready";
const OUTCOME_ERROR: &str = "error";

/// How many consecutive `NotReady` answers to tolerate before re-resolving the
/// operator. An operator that has not read this subnet's node list yet picks it
/// up with its next registry refetch, so a genuinely fresh operator recovers
/// well within this budget; an operator that keeps not recognizing this node
/// more likely is not (or no longer) our operator at all. At one check every 10
/// seconds this is about 5 minutes.
const MAX_CONSECUTIVE_NOT_READY: u32 = 30;

pub(crate) struct CloudEngineManager {
    registry: Arc<RegistryHelper>,
    /// The assignment the upgrade loop determined, shared with the other tasks
    /// that need to know which subnet this node serves.
    subnet_assignment: Arc<RwLock<SubnetAssignment>>,
    crypto: Arc<dyn NodeRegistrationCrypto>,
    replica_url: Url,
    /// The agent that signs as this node, built on first use and then reused:
    /// everything it depends on is stable.
    operator_agent: Option<Agent>,
    discovery: Discovery,
    /// The last config that passed validation, shared with the process manager
    /// that runs `ic-gateway`. Only ever replaced by another valid one, never
    /// cleared: a failed fetch must not take a running `ic-gateway` down.
    current_config: Arc<RwLock<Option<EngineConfig>>>,
    consecutive_not_ready: u32,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl CloudEngineManager {
    /// `replica_url` addresses the replica running on this node, which serves
    /// the calls to the operator canister on this node's own subnet.
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        subnet_assignment: Arc<RwLock<SubnetAssignment>>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        engine_management_canister_id: CanisterId,
        replica_url: Url,
        current_config: Arc<RwLock<Option<EngineConfig>>>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let discovery = Discovery::new(
            Arc::clone(&registry),
            engine_management_canister_id,
            logger.clone(),
        );

        Self {
            registry,
            subnet_assignment,
            crypto,
            replica_url,
            operator_agent: None,
            discovery,
            current_config,
            consecutive_not_ready: 0,
            metrics,
            logger,
        }
    }

    /// Refreshes the engine configuration, keeping the previous one on failure.
    pub(crate) async fn check(&mut self) {
        let subnet_id = match *self.subnet_assignment.read().unwrap() {
            SubnetAssignment::Assigned(subnet_id) => subnet_id,
            // Unassigned nodes are not part of an engine, and while the
            // assignment is unknown there is nothing to go on: the upgrade
            // loop determines it on its first run.
            SubnetAssignment::Unassigned | SubnetAssignment::Unknown => return,
        };
        let version = self.registry.get_latest_version();
        // Only all-in-one nodes have an engine operator to ask.
        match self.registry.is_cloud_engine_subnet(subnet_id, version) {
            Ok(true) => {}
            Ok(false) => return,
            // On an engine node a registry error would otherwise be invisible:
            // it must not be conflated with "not a cloud engine".
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

    /// Records what a fetch produced: publishes a new configuration, and keeps
    /// the operator lookup honest by discarding it when the operator stops
    /// answering usefully.
    fn apply(&mut self, outcome: CloudEngineResult<EngineConfig>) {
        match outcome {
            Ok(new_config) => {
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_OK])
                    .inc();
                self.metrics
                    .cloud_engine_config_last_success
                    .set(current_time().as_secs_since_unix_epoch() as i64);

                let mut current_config = self.current_config.write().unwrap();
                if current_config.as_ref() != Some(&new_config) {
                    info!(self.logger, "New engine configuration: {:?}", new_config);
                    *current_config = Some(new_config);
                }
            }
            Err(CloudEngineError::Incomplete(field)) => {
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_INCOMPLETE])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger, "The engine is not fully configured yet: {} is not set", field
                );
            }
            Err(CloudEngineError::NotReady) => {
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_NOT_READY])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger,
                    "The engine operator does not recognize this node yet; retrying"
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
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_ERROR])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger, "Could not read the engine configuration: {}", err
                );
                // An operator that answers with anything but "not ready" may
                // not be our operator at all, so look it up again next time.
                // A failure before the operator was even reached has nothing
                // remembered to discard.
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

        let operator_agent = self.operator_agent(version)?;
        let operator = OperatorClient::new(&operator_agent, operator_id);

        let http_gateway_config = operator.http_gateway_config().await?;
        let acme_credentials = operator.acme_credentials().await?;

        validate_engine_config(http_gateway_config, acme_credentials)
    }

    /// The agent the operator canister is called with, built on first use.
    fn operator_agent(&mut self, version: RegistryVersion) -> CloudEngineResult<Agent> {
        if let Some(agent) = &self.operator_agent {
            return Ok(agent.clone());
        }

        let agent = agent::node_signed(
            self.registry.get_registry_client(),
            Arc::clone(&self.crypto),
            self.replica_url.clone(),
            version,
        )?;
        self.operator_agent = Some(agent.clone());

        Ok(agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::NODE_1;

    /// The operator this node has resolved before the outcome under test.
    fn operator() -> CanisterId {
        CanisterId::from_u64(3)
    }

    /// A manager that has already resolved [`operator`]. It never reaches the
    /// network: the tests drive [`CloudEngineManager::apply`] directly with the
    /// outcome a fetch would have produced.
    fn manager_for_test() -> CloudEngineManager {
        let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(
            ProtoRegistryDataProvider::new(),
        )));
        registry_client.update_to_latest_version();
        let registry = Arc::new(RegistryHelper::new(NODE_1, registry_client, no_op_logger()));

        let mut manager = CloudEngineManager::new(
            registry,
            Arc::new(RwLock::new(SubnetAssignment::Unknown)),
            Arc::new(CryptoReturningOk::default()),
            CanisterId::from_u64(1000),
            Url::parse("http://127.0.0.1:8080/").unwrap(),
            Arc::new(RwLock::new(None)),
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        );
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

        manager.apply(Ok(EngineConfig::for_test("engine.example.com")));

        assert_eq!(
            *manager.current_config.read().unwrap(),
            Some(EngineConfig::for_test("engine.example.com"))
        );
        assert_eq!(fetches(&manager, OUTCOME_OK), 1);
        // A configuration was served, so the operator stays resolved.
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }

    #[test]
    fn an_incomplete_configuration_keeps_the_previous_one() {
        let mut manager = manager_for_test();
        manager.apply(Ok(EngineConfig::for_test("engine.example.com")));

        manager.apply(Err(CloudEngineError::Incomplete("dns_api_urls")));

        // An engine that is being configured must not take `ic-gateway` down,
        // and it is the operator we expect, so it stays resolved.
        assert_eq!(
            *manager.current_config.read().unwrap(),
            Some(EngineConfig::for_test("engine.example.com"))
        );
        assert_eq!(fetches(&manager, OUTCOME_INCOMPLETE), 1);
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }

    #[test]
    fn a_failure_keeps_the_configuration_but_re_resolves_the_operator() {
        let mut manager = manager_for_test();
        manager.apply(Ok(EngineConfig::for_test("engine.example.com")));

        manager.apply(Err(CloudEngineError::failed("the operator is on fire")));

        assert_eq!(
            *manager.current_config.read().unwrap(),
            Some(EngineConfig::for_test("engine.example.com"))
        );
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
        for _ in 0..MAX_CONSECUTIVE_NOT_READY - 1 {
            manager.apply(Err(CloudEngineError::NotReady));
        }

        manager.apply(Ok(EngineConfig::for_test("engine.example.com")));

        assert_eq!(manager.consecutive_not_ready, 0);

        // The next `NotReady` starts over, so the operator is kept.
        manager.apply(Err(CloudEngineError::NotReady));

        assert_eq!(manager.consecutive_not_ready, 1);
        assert_eq!(manager.discovery.remembered(), Some(operator()));
    }
}
