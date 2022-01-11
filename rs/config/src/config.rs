//! This module defines the `Config` data structure which is the
//! config for the (almost) entire replica and related parsing
//! functions.  Each component that has an individual Config should
//! get included here so that it can be parsed.

use crate::{
    artifact_pool::ArtifactPoolTomlConfig,
    config_parser::{ConfigError, ConfigSource, ConfigValidate},
    consensus::ConsensusConfig,
    crypto::CryptoConfig,
    execution_environment::Config as HypervisorConfig,
    firewall::Config as FirewallConfig,
    http_handler,
    http_handler::Config as HttpHandlerConfig,
    logger::Config as LoggerConfig,
    message_routing::Config as MessageRoutingConfig,
    metrics::Config as MetricsConfig,
    nns_registry_replicator::Config as NnsRegistryReplicatorConfig,
    registration::Config as RegistrationConfig,
    registry_client::Config as RegistryClientConfig,
    state_manager::Config as StateManagerConfig,
};
use ic_types::{malicious_behaviour::MaliciousBehaviour, transport::TransportConfig};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};

/// The config struct for the replica.  Just consists of `Config`s for
/// the components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub registry_client: RegistryClientConfig,
    pub transport: TransportConfig,
    pub state_manager: StateManagerConfig,
    pub hypervisor: HypervisorConfig,
    pub http_handler: HttpHandlerConfig,
    pub metrics: MetricsConfig,
    pub artifact_pool: ArtifactPoolTomlConfig,
    pub consensus: ConsensusConfig,
    pub crypto: CryptoConfig,
    pub logger: LoggerConfig,
    // If `orchestrator_logger` is not specified in the configuration file, it
    // defaults to the value specified for `logger`.
    pub orchestrator_logger: LoggerConfig,
    pub message_routing: MessageRoutingConfig,
    pub malicious_behaviour: MaliciousBehaviour,
    pub firewall: FirewallConfig,
    pub registration: RegistrationConfig,
    pub nns_registry_replicator: NnsRegistryReplicatorConfig,
}

/// Mirrors the Config struct except that fields are made optional. This is
/// meant for use with config_parser, where sections can be omitted.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ConfigOptional {
    pub registry_client: Option<RegistryClientConfig>,
    pub transport: Option<TransportConfig>,
    pub state_manager: Option<StateManagerConfig>,
    pub hypervisor: Option<HypervisorConfig>,
    pub http_handler: Option<http_handler::ExternalConfig>,
    pub metrics: Option<MetricsConfig>,
    pub artifact_pool: Option<ArtifactPoolTomlConfig>,
    pub consensus: Option<ConsensusConfig>,
    pub crypto: Option<CryptoConfig>,
    pub logger: Option<LoggerConfig>,
    pub orchestrator_logger: Option<LoggerConfig>,
    pub message_routing: Option<MessageRoutingConfig>,
    pub malicious_behaviour: Option<MaliciousBehaviour>,
    pub firewall: Option<FirewallConfig>,
    pub registration: Option<RegistrationConfig>,
    pub nns_registry_replicator: Option<NnsRegistryReplicatorConfig>,
}

impl Config {
    /// Return a [Config] with default settings that put all paths under a
    /// 'parent_dir', with the given 'subnet_id'.
    ///
    /// It is an alternative way to construct a Config than parsing
    /// a configuration file.
    pub fn new(parent_dir: std::path::PathBuf) -> Self {
        let logger = LoggerConfig::default();
        Self {
            registry_client: RegistryClientConfig::default(),
            transport: TransportConfig::default(),
            state_manager: StateManagerConfig::new(parent_dir.join("state")),
            hypervisor: HypervisorConfig::default(),
            http_handler: HttpHandlerConfig::default(),
            metrics: MetricsConfig::default(),
            artifact_pool: ArtifactPoolTomlConfig::new(parent_dir.join("consensus_pool"), None),
            consensus: ConsensusConfig::default(),
            crypto: CryptoConfig::new(parent_dir.join("crypto")),
            logger: logger.clone(),
            orchestrator_logger: logger,
            message_routing: MessageRoutingConfig::default(),
            malicious_behaviour: MaliciousBehaviour::default(),
            firewall: FirewallConfig::default(),
            registration: RegistrationConfig::default(),
            nns_registry_replicator: NnsRegistryReplicatorConfig::default(),
        }
    }

    /// Run a function with default [Config] created with temporary directories
    /// that are automatically removed after the function finishes.
    pub fn run_with_temp_config<T>(run: impl FnOnce(Self) -> T) -> T {
        let (config, _tmpdir) = Self::temp_config();
        run(config)
    }

    /// Return a function with default [Config] created with temporary
    /// directories that are automatically removed once `TempDir` is
    /// dropped. `TempDir` should remain in scope for the duration where the
    /// `Config` is being used.
    pub fn temp_config() -> (Self, tempfile::TempDir) {
        let tmpdir = tempfile::Builder::new()
            .prefix("ic_config")
            .tempdir()
            .unwrap();
        (Self::new(tmpdir.path().to_path_buf()), tmpdir)
    }

    /// Load [Config] from the given 'config_descr' where if a section is
    /// omitted, its value is taken from the given 'default'.
    pub fn load_with_default(source: &ConfigSource, default: Config) -> Result<Self, ConfigError> {
        let cfg = source.load::<ConfigOptional>()?;

        let logger = cfg.logger.unwrap_or(default.logger);
        let orchestrator_logger = cfg.orchestrator_logger.unwrap_or_else(|| logger.clone());

        Ok(Self {
            registry_client: cfg.registry_client.unwrap_or(default.registry_client),
            transport: cfg.transport.unwrap_or(default.transport),
            state_manager: cfg.state_manager.unwrap_or(default.state_manager),
            hypervisor: cfg.hypervisor.unwrap_or(default.hypervisor),
            http_handler: HttpHandlerConfig::try_from(cfg.http_handler).map_err(|msg| {
                ConfigError::ValidationError {
                    source: source.clone(),
                    message: msg.to_string(),
                }
            })?,
            metrics: cfg.metrics.unwrap_or(default.metrics),
            artifact_pool: cfg.artifact_pool.unwrap_or(default.artifact_pool),
            consensus: cfg.consensus.unwrap_or(default.consensus),
            crypto: cfg.crypto.unwrap_or(default.crypto),
            logger,
            orchestrator_logger,
            message_routing: cfg.message_routing.unwrap_or(default.message_routing),
            malicious_behaviour: cfg
                .malicious_behaviour
                .unwrap_or(default.malicious_behaviour),
            firewall: cfg.firewall.unwrap_or(default.firewall),
            registration: cfg.registration.unwrap_or(default.registration),
            nns_registry_replicator: cfg
                .nns_registry_replicator
                .unwrap_or(default.nns_registry_replicator),
        })
    }

    /// Load the Replica config from the given source
    pub fn load_with_tmpdir(config_source: ConfigSource, tmpdir: PathBuf) -> Config {
        let default_config = Config::new(tmpdir);

        Config::load_with_default(&config_source, default_config).unwrap_or_else(|err| {
            eprintln!("Failed to load config:\n  {}", err);
            std::process::exit(1);
        })
    }
}

impl ConfigValidate for ConfigOptional {
    fn validate(self) -> Result<Self, String> {
        Ok(self)
    }
}
