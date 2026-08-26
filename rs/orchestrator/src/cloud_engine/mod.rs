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
use config::{ConfigError, GatewayConfig};
use discovery::Discovery;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_logger::{ReplicaLogger, info, warn};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_types::{CanisterId, RegistryVersion};
use operator::{OperatorClient, OperatorError};
use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc, time::SystemTime};
use url::Url;

/// Value of the `outcome` label of `cloud_engine_config_fetches`.
const OUTCOME_OK: &str = "ok";
const OUTCOME_INCOMPLETE: &str = "incomplete";
const OUTCOME_NOT_READY: &str = "not_ready";
const OUTCOME_ERROR: &str = "error";

pub(crate) struct CloudEngineManager {
    registry: Arc<RegistryHelper>,
    agent_factory: agent::AgentFactory,
    discovery: Discovery,
    /// The last config that passed validation. Only ever replaced by another
    /// valid one, never cleared: a failed fetch must not take a running
    /// `ic-gateway` down.
    current_config: Option<GatewayConfig>,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl CloudEngineManager {
    /// Returns `None` when the node has no engine management canister
    /// configured, in which case it cannot find its operator and this manager
    /// has nothing to do.
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        tls_config: Arc<dyn TlsConfig>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        engine_management_canister_id: Option<&str>,
        replica_listen_addr: SocketAddr,
        data_directory: &Path,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Option<Self> {
        let engine_management_canister_id = engine_management_canister_id?;
        let engine_management_canister_id =
            match CanisterId::from_str(engine_management_canister_id) {
                Ok(canister_id) => canister_id,
                Err(err) => {
                    warn!(
                        logger,
                        "Ignoring the malformed engine management canister id \
                    '{}': {}",
                        engine_management_canister_id,
                        err
                    );
                    return None;
                }
            };

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

        let agent_factory = agent::AgentFactory::new(
            Arc::clone(&registry),
            tls_config,
            crypto,
            replica_url,
            logger.clone(),
        );
        let discovery = Discovery::new(
            Arc::clone(&registry),
            engine_management_canister_id,
            data_directory,
            logger.clone(),
        );

        Some(Self {
            registry,
            agent_factory,
            discovery,
            current_config: None,
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
        match self.registry.get_subnet_type(subnet_id, version) {
            Ok(Some(SubnetType::CloudEngine)) => {}
            _ => return,
        }

        match self.fetch(version).await {
            Ok(config) => {
                self.metrics
                    .cloud_engine_config_fetches
                    .with_label_values(&[OUTCOME_OK])
                    .inc();
                self.metrics
                    .cloud_engine_config_last_success
                    .set(unix_timestamp());

                if self.current_config.as_ref() != Some(&config) {
                    info!(self.logger, "New engine configuration: {:?}", config);
                    self.current_config = Some(config);
                }
            }
            Err(FetchError::Incomplete(err)) => {
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
            }
            Err(FetchError::Failed(err)) => {
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

    async fn fetch(&mut self, version: RegistryVersion) -> Result<GatewayConfig, FetchError> {
        let own_subnet = self.registry.get_subnet_id(version)?;

        let management_subnet = self.discovery.management_subnet(version)?;
        let management_agent = self
            .agent_factory
            .anonymous_to_subnet(management_subnet, version)?;
        let operator_id = self
            .discovery
            .resolve(&management_agent, own_subnet, version)
            .await?;

        let operator_agent = self.agent_factory.node_signed_to_local_replica(version)?;
        let operator = OperatorClient::new(&operator_agent, operator_id);

        let gateway_config = match operator.http_gateway_config().await {
            Ok(config) => config,
            Err(err) => {
                // A cold `isNode` cache is expected; anything else suggests we
                // resolved the wrong canister, so look it up again next time.
                if matches!(err, OperatorError::Failed(_)) {
                    self.discovery.invalidate();
                }
                return Err(err.into());
            }
        };
        let acme_credentials = operator.acme_credentials().await?;

        GatewayConfig::try_from((gateway_config, acme_credentials)).map_err(FetchError::from)
    }
}

/// Why [`CloudEngineManager::fetch`] did not produce a config.
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
