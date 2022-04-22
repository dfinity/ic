use crate::registry_helper::RegistryHelper;
use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
};
use ic_config::firewall::{Config as FirewallConfig, FIREWALL_FILE_DEFAULT_PATH};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::registry::firewall::v1::FirewallConfig as FirewallConfigPB;
use ic_types::RegistryVersion;
use ic_utils::fs::write_string_using_tmp_file;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
enum DataSource {
    Config,
    Registry,
}

/// Provides function to continuously check the Registry to determine if there
/// has been a change in the firewall config, and if so, updates the node's
/// firewall rules file accordingly.
pub(crate) struct Firewall {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
    configuration: FirewallConfig,
    source: DataSource,
    compiled_config: String,
    // If true, write the file content even if no change was detected in registry, i.e. first time
    must_write: bool,
    // If false, do not update the firewall rules (test mode)
    enabled: bool,
}

impl Firewall {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        firewall_config: FirewallConfig,
        logger: ReplicaLogger,
    ) -> Self {
        let config = firewall_config.clone();

        // Disable if the config is the default one (e.g if we're in a test)
        let enabled = firewall_config
            .config_file
            .ne(&PathBuf::from(FIREWALL_FILE_DEFAULT_PATH));

        if !enabled {
            warn!(
                logger,
                "Firewall configuration not found. Orchestrator does not update firewall rules."
            );
        }

        Self {
            registry,
            metrics,
            configuration: config,
            source: DataSource::Config,
            logger,
            compiled_config: Default::default(),
            must_write: true,
            enabled,
        }
    }

    fn update_config_from_pb(&mut self, pb: FirewallConfigPB) {
        self.configuration.firewall_config = pb.firewall_config;
        self.configuration.ipv4_prefixes = pb.ipv4_prefixes;
        self.configuration.ipv6_prefixes = pb.ipv6_prefixes;
    }

    fn check_for_firewall_config(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        match self.registry.get_firewall_config(registry_version) {
            Ok(registry_fw_config) => {
                // Data found in registry!
                self.update_config_from_pb(registry_fw_config);
                self.source = DataSource::Registry;
            }
            Err(e) => {
                // No data was found in registry
                match self.source {
                    DataSource::Registry => warn!(
                        every_n_seconds => 300,
                        self.logger,
                        "Firewall configuration was not found in registry. Using previously fetched data. (Error from registry: {:?})",
                        e
                    ),
                    // In case we have never found data in registry:
                    DataSource::Config => warn!(
                        every_n_seconds => 300,
                        self.logger,
                        "Firewall configuration was not found in registry. Using config file instead. (Error from registry: {:?})",
                        e
                    ),
                };
            }
        }

        let content = self.generate_firewall_file_content_full();

        let changed = content.ne(&self.compiled_config);
        if changed {
            // Firewall config is different - update it
            info!(
                self.logger,
                "New firewall configuration found (source: {:?}). Updating local firewall.",
                self.source
            );
        }

        if changed || self.must_write {
            if content.is_empty() {
                warn!(
                    self.logger,
                    "No firewall configuration found. Orchestrator will not write any config to a file."
                );
            } else {
                let f = &self.configuration.config_file;
                write_string_using_tmp_file(f, content.as_str())
                    .map_err(|e| OrchestratorError::file_write_error(f, e))?;
                self.compiled_config = content;
            }
            self.must_write = false;
        }

        Ok(())
    }

    /// Generates a string with the content for the firewall rules file
    fn generate_firewall_file_content_full(&self) -> String {
        self.configuration
            .firewall_config
            .replace(
                "<< ipv4_prefixes >>",
                &Self::sanitize_prefixes(&self.configuration.ipv4_prefixes).join(",\n"),
            )
            .replace(
                "<< ipv6_prefixes >>",
                &Self::sanitize_prefixes(&self.configuration.ipv6_prefixes).join(",\n"),
            )
    }

    fn sanitize_prefixes(prefixes: &[String]) -> Vec<String> {
        prefixes
            .iter()
            .map(|prefix| prefix.replace(',', "").replace('\n', ""))
            .collect()
    }

    /// Checks for new firewall config, and if found, update local firewall
    /// rules
    pub fn check_and_update(&mut self) {
        if !self.enabled {
            return;
        }
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking for firewall config registry version: {}", registry_version
        );

        match self.check_for_firewall_config(registry_version) {
            Ok(()) => self
                .metrics
                .datacenter_registry_version
                .set(registry_version.get() as i64),
            Err(e) => info!(
                self.logger,
                "Failed to check for firewall config at version {}: {}", registry_version, e
            ),
        };
    }
}
