use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    registry_helper::RegistryHelper,
};
use ic_logger::{ReplicaLogger, debug, info, warn};
use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_types::RegistryVersion;
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::process::Command;

/// Provides function to check the registry to determine if there
/// has been a change in the IPv4 config, and if so, updates the node's
/// network configuration accordingly.
pub(crate) struct Ipv4Configurator {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
    last_applied_version: Arc<RwLock<RegistryVersion>>,
    ic_binary_dir: PathBuf,
    configuration: Option<IPv4InterfaceConfig>,
}

impl Ipv4Configurator {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        ic_binary_dir: PathBuf,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            metrics,
            logger,
            last_applied_version: Default::default(),
            ic_binary_dir,
            configuration: None,
        }
    }

    /// Applies an IPv4 conifguration of that node changed and applies it
    async fn apply_ipv4_config_change(
        &mut self,
        ipv4_config: Option<IPv4InterfaceConfig>,
    ) -> OrchestratorResult<()> {
        // call the helper to configure the interface
        info!(
            self.logger,
            "Attempting to apply the new IPv4 configuration."
        );
        match &self.configuration {
            Some(config) => info!(
                self.logger,
                "Current IPv4 config: address={}/{}, gateway={}.",
                config.ip_addr,
                config.prefix_length,
                config.gateway_ip_addr.first().unwrap_or(&"n/a".to_string())
            ),
            None => info!(self.logger, "Current IPv4 config: no configuration."),
        }

        match &ipv4_config {
            Some(config) => info!(
                self.logger,
                "New IPv4 config: address={}/{}, gateway={}.",
                config.ip_addr,
                config.prefix_length,
                config.gateway_ip_addr.first().unwrap_or(&"n/a".to_string())
            ),
            None => info!(self.logger, "New IPv4 config: no configuration."),
        }

        let script = self.ic_binary_dir.join("guestos_tool");
        let mut cmd = Command::new("sudo");

        cmd.arg(script.into_os_string())
            .arg("regenerate-network-config");

        if let Some(config) = &ipv4_config {
            cmd.arg(format!("--ipv4-address={}", config.ip_addr))
                .arg(format!("--ipv4-prefix-length={}", config.prefix_length))
                .arg(format!(
                    "--ipv4-gateway={}",
                    config.gateway_ip_addr.first().expect("missing gateway")
                ));
        }

        let out = cmd
            .output()
            .await
            .map_err(|e| OrchestratorError::NetworkConfigurationError(e.to_string()))?;

        if !out.status.success() {
            return Err(OrchestratorError::NetworkConfigurationError(format!(
                "guestos_tool failed to regenerate the network config: {:?} - stdout: {} - stderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        } else {
            info!(
                self.logger,
                "successfully applied the new network config - stdout: {} - stderr: {}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            );

            // after successfully applying the configuration, update the state
            self.configuration = ipv4_config;
        }

        Ok(())
    }

    /// Checks for a change in the IPv4 configuration, and if found, updates the
    /// local network configuration
    pub async fn check_and_update(&mut self) {
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking IPv4 config at registry version: {}", registry_version
        );

        // fetch the IPv4 config from the registry
        let ipv4_config = match self.registry.get_node_ipv4_config(registry_version) {
            Ok(config) => config,
            Err(e) => {
                warn!(
                    self.logger,
                    "Failed to fetch the IPv4 config from the registry at version {}: {}",
                    registry_version,
                    e
                );
                return; // Early return on error
            }
        };

        // check if the configuration changed and if so, apply the changes
        if self.configuration != ipv4_config {
            match self.apply_ipv4_config_change(ipv4_config).await {
                Ok(()) => self
                    .metrics
                    .ipv4_registry_version
                    .set(registry_version.get() as i64),
                Err(e) => {
                    warn!(
                        self.logger,
                        "Failed to apply the IPv4 config at version {}: {}", registry_version, e
                    );
                    return;
                }
            };
        };

        // keep track of the last successfully applied registry version (even if there was no change in the IPv4 config)
        *self.last_applied_version.write().unwrap() = registry_version;
    }

    pub fn get_last_applied_version(&self) -> Arc<RwLock<RegistryVersion>> {
        Arc::clone(&self.last_applied_version)
    }
}
