//! This module defines the `Config` data structure which is the
//! config for the (almost) entire replica and related parsing
//! functions.  Each component that has an individual Config should
//! get included here so that it can be parsed.

use crate::{
    adapters::AdaptersConfig,
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
    transport::TransportConfig,
};
use ic_types::malicious_behaviour::MaliciousBehaviour;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom, path::PathBuf};

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
    pub adapters_config: AdaptersConfig,
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
    pub adapters_config: Option<AdaptersConfig>,
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
            adapters_config: AdaptersConfig::default(),
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
            adapters_config: cfg.adapters_config.unwrap_or(default.adapters_config),
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
        let mut same_uds_paths = false;
        if let Some(adapters_config) = &self.adapters_config {
            let mut uds_paths = HashSet::new();
            if let Some(uds_path) = &adapters_config.bitcoin_mainnet_uds_path {
                same_uds_paths |= !uds_paths.insert(uds_path.clone());
            }
            if let Some(uds_path) = &adapters_config.bitcoin_testnet_uds_path {
                same_uds_paths |= !uds_paths.insert(uds_path.clone());
            }
            if let Some(uds_path) = &adapters_config.canister_http_uds_path {
                same_uds_paths |= !uds_paths.insert(uds_path.clone());
            }
            if same_uds_paths {
                return Err(
                    "Inside Config::adapters_config at least two UDS paths are the same."
                        .to_string(),
                );
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sample::SAMPLE_CONFIG;
    use tempfile::tempdir as tempdir_deleted_at_end_of_scope;

    #[test]
    fn load_with_default_works_on_old_configs() {
        let csp_vault_type_entry = "csp_vault_type: { unix_socket: \"/some/path/to/socket\" },";
        let sample_config_without_csp_vault_type = SAMPLE_CONFIG.replace(csp_vault_type_entry, "");
        let result = json5::from_str::<Config>(&sample_config_without_csp_vault_type);
        assert!(
            result.is_ok(),
            "JSON5 parsing failed with error: {:?}",
            result
        );

        let temp_dir = tempdir_deleted_at_end_of_scope().expect("Failed creating a temp file.");
        let old_config_file = temp_dir.path().join("old_ic.json5");
        std::fs::write(&old_config_file, &sample_config_without_csp_vault_type)
            .expect("Failed writing test config to a file.");
        let source = ConfigSource::File(old_config_file);
        let default_config = Config::new(temp_dir.path().to_path_buf());
        let result = Config::load_with_default(&source, default_config);
        assert!(
            result.is_ok(),
            "load_with_default failed with error: {:?}",
            result
        );
        // Check that `crypto_root` is from `SAMPLE_CONFIG`, not from `CryptoConfig::default()`.
        assert_eq!(
            result
                .expect("Expected Config")
                .crypto
                .crypto_root
                .to_str()
                .expect("Expected path string"),
            "/tmp/ic_crypto"
        );
    }
}
