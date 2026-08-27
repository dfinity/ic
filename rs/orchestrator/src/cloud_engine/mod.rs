//! Keeps track of the `ic-gateway` configuration of a cloud engine node.
//!
//! Cloud engine subnets are self-contained: each one has an `engine-operator`
//! canister on the subnet itself that holds the base domains the engine serves,
//! a DNS provider API for the ACME dns-01 challenge, and the ACME account to
//! renew certificates with. This module polls that canister and hands the result
//! to whoever runs `ic-gateway`.

mod agent;
mod config;
mod discovery;
mod operator;

use crate::{
    error::OrchestratorError, metrics::OrchestratorMetrics, registration::NodeRegistrationCrypto,
    registry_helper::RegistryHelper,
};
use config::ConfigError;
pub(crate) use config::GatewayConfig;
use discovery::Discovery;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{CanisterId, RegistryVersion, SubnetId};
use operator::{OperatorClient, OperatorError};
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::SystemTime,
};
use url::Url;

/// Value of the `outcome` label of `cloud_engine_config_fetches`.
const OUTCOME_OK: &str = "ok";
const OUTCOME_INCOMPLETE: &str = "incomplete";
const OUTCOME_NOT_READY: &str = "not_ready";
const OUTCOME_ERROR: &str = "error";

/// How many consecutive `NotReady` answers to tolerate before re-resolving the
/// operator. A cold `isNode` cache resolves itself with the operator's next
/// registry refetch, so a genuinely fresh operator recovers well within this
/// budget; an operator that keeps not recognizing this node more likely is not
/// (or no longer) our operator at all. At one check every 10 seconds this is
/// about 5 minutes.
const MAX_CONSECUTIVE_NOT_READY: u32 = 30;

pub(crate) struct CloudEngineManager {
    registry: Arc<RegistryHelper>,
    agent_factory: agent::AgentFactory,
    discovery: Discovery,
    /// The last config that passed validation, shared with the process manager
    /// that runs `ic-gateway`. Only ever replaced by another valid one, never
    /// cleared: a failed fetch must not take a running `ic-gateway` down.
    current_config: Arc<RwLock<Option<GatewayConfig>>>,
    consecutive_not_ready: u32,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl CloudEngineManager {
    /// Returns `None` when the node has no engine management canister
    /// configured, in which case it cannot find its operator and this manager
    /// has nothing to do.
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        engine_management_canister_id: Option<CanisterId>,
        replica_listen_addr: SocketAddr,
        current_config: Arc<RwLock<Option<GatewayConfig>>>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Option<Self> {
        let engine_management_canister_id = engine_management_canister_id?;

        // The replica listens on a wildcard address, so only its port is of
        // use here: the operator canister is on this node's own subnet and is
        // therefore reached over the loopback interface.
        let replica_url =
            match Url::parse(&format!("http://127.0.0.1:{}", replica_listen_addr.port())) {
                Ok(url) => url,
                Err(err) => {
                    warn!(logger, "Cannot address the local replica: {}", err);
                    return None;
                }
            };

        let agent_factory =
            agent::AgentFactory::new(Arc::clone(&registry), crypto, replica_url, logger.clone());
        let discovery = Discovery::new(
            Arc::clone(&registry),
            engine_management_canister_id,
            logger.clone(),
        );

        Some(Self {
            registry,
            agent_factory,
            discovery,
            current_config,
            consecutive_not_ready: 0,
            metrics,
            logger,
        })
    }

    /// Refreshes the engine configuration, keeping the previous one on failure.
    pub(crate) async fn check(&mut self) {
        let version = self.registry.get_latest_version();
        let subnet_id = match self.registry.get_subnet_id(version) {
            Ok(subnet_id) => subnet_id,
            // Unassigned nodes are not part of an engine.
            Err(_) => return,
        };
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

        match self.fetch(subnet_id, version).await {
            Ok(config) => {
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_OK])
                    .inc();
                self.metrics
                    .cloud_engine_config_last_success
                    .set(unix_timestamp());

                let mut current_config = self.current_config.write().unwrap();
                if current_config.as_ref() != Some(&config) {
                    info!(self.logger, "New engine configuration: {:?}", config);
                    *current_config = Some(config);
                }
            }
            Err(FetchError::Incomplete(err)) => {
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_INCOMPLETE])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger, "The engine is not fully configured yet: {}", err
                );
            }
            Err(FetchError::NotReady) => {
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
            Err(FetchError::Failed(err)) => {
                self.consecutive_not_ready = 0;
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_ERROR])
                    .inc();
                warn!(
                    every_n_seconds => 60,
                    self.logger, "Could not read the engine configuration: {}", err
                );
            }
        }
    }

    async fn fetch(
        &mut self,
        own_subnet: SubnetId,
        version: RegistryVersion,
    ) -> Result<GatewayConfig, FetchError> {
        let operator_id = self
            .discovery
            .resolve(&self.agent_factory, own_subnet, version)
            .await?;

        let operator_agent = self.agent_factory.node_signed_to_local_replica(version)?;
        let operator = OperatorClient::new(&operator_agent, operator_id);

        let result = async {
            let gateway_config = operator.http_gateway_config().await?;
            let acme_credentials = operator.acme_credentials().await?;
            Ok::<_, OperatorError>((gateway_config, acme_credentials))
        }
        .await;
        let (gateway_config, acme_credentials) = match result {
            Ok(parts) => parts,
            Err(err) => {
                // A cold `isNode` cache is expected; anything else suggests we
                // resolved the wrong canister, so look it up again next time.
                if matches!(err, OperatorError::Failed(_)) {
                    self.discovery.invalidate();
                }
                return Err(err.into());
            }
        };

        GatewayConfig::try_from((gateway_config, acme_credentials)).map_err(FetchError::from)
    }
}

enum FetchError {
    /// The engine is not fully configured yet. Nothing to apply.
    Incomplete(String),
    /// The operator does not recognize this node yet.
    NotReady,
    Failed(String),
}

impl From<OrchestratorError> for FetchError {
    fn from(err: OrchestratorError) -> Self {
        Self::Failed(err.to_string())
    }
}

impl From<OperatorError> for FetchError {
    fn from(err: OperatorError) -> Self {
        match err {
            OperatorError::NotReady => Self::NotReady,
            OperatorError::Failed(err) => Self::Failed(err),
        }
    }
}

impl From<ConfigError> for FetchError {
    fn from(err: ConfigError) -> Self {
        match err {
            ConfigError::Incomplete(_) => Self::Incomplete(err.to_string()),
            ConfigError::Invalid(_) => Self::Failed(err.to_string()),
        }
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs() as i64)
}
