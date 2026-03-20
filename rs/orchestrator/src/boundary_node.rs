use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessManager},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{NodeId, ReplicaVersion};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct BoundaryNodeProcess {
    version: ReplicaVersion,
    binary: String,
    args: Vec<String>,
    env: HashMap<String, String>,
}

impl Process for BoundaryNodeProcess {
    const NAME: &'static str = "Boundary Node";

    type Version = ReplicaVersion;

    fn get_version(&self) -> &Self::Version {
        &self.version
    }

    fn get_binary(&self) -> &str {
        &self.binary
    }

    fn get_args(&self) -> &[String] {
        &self.args
    }

    fn get_env(&self) -> HashMap<String, String> {
        self.env.clone()
    }
}

pub(crate) struct BoundaryNodeManager {
    registry: Arc<RegistryHelper>,
    _metrics: Arc<OrchestratorMetrics>,
    process: Arc<Mutex<ProcessManager<BoundaryNodeProcess>>>,
    ic_binary_dir: PathBuf,
    crypto_config: CryptoConfig,
    version: ReplicaVersion,
    logger: ReplicaLogger,
    node_id: NodeId,
    domain_name: Option<String>,
}

impl BoundaryNodeManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        version: ReplicaVersion,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        crypto_config: CryptoConfig,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            _metrics: metrics,
            process: Arc::new(Mutex::new(ProcessManager::new(logger.clone()))),
            ic_binary_dir,
            crypto_config,
            version,
            logger,
            node_id,
            domain_name: None,
        }
    }

    pub(crate) async fn check(&mut self) {
        let registry_version = self.registry.get_latest_version();

        match self
            .registry
            .get_api_boundary_node_version(self.node_id, registry_version)
        {
            Ok(replica_version) => {
                // BN manager is waiting for Upgrade to be performed
                if replica_version != self.version {
                    warn!(
                        every_n_seconds => 60,
                        self.logger, "Boundary node runs outdated version ({:?}), expecting upgrade to {:?}", self.version, replica_version
                    );
                    // NOTE: We could also shutdown the boundary node here. However, it makes sense to continue
                    // serving requests while the orchestrator is downloading the new image in most cases.
                } else {
                    match self.registry.get_node_domain_name(registry_version) {
                        Ok(Some(domain_name)) => {
                            let domain_name = Some(domain_name);

                            // stop ic-boundary when the domain name changes and start it again.
                            if domain_name != self.domain_name {
                                if let Err(err) = self.ensure_boundary_node_stopped() {
                                    warn!(self.logger, "Failed to stop Boundary Node: {}", err);
                                }
                                self.domain_name = domain_name;
                            }

                            // make sure the boundary node is running
                            if let Err(err) = self.ensure_boundary_node_running(&self.version) {
                                warn!(self.logger, "Failed to start Boundary Node: {}", err);
                            }
                        }
                        // BN should not be active when the node doesn't have a domain name
                        Ok(None) => {
                            warn!(
                                self.logger,
                                "There is no domain associated with the node, while this is a requirement for the API boundary node. Shutting ic-boundary down."
                            );
                            if let Err(err) = self.ensure_boundary_node_stopped() {
                                warn!(self.logger, "Failed to stop Boundary Node: {}", err);
                            }
                            self.domain_name = None;
                        }
                        // Failing to read the registry
                        Err(err) => warn!(
                            self.logger,
                            "Failed to fetch Boundary Node domain name: {}", err
                        ),
                    }
                }
            }
            // BN should not be active
            Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)) => {
                if let Err(err) = self.ensure_boundary_node_stopped() {
                    warn!(self.logger, "Failed to stop Boundary Node: {}", err);
                }
            }
            // Failing to read the registry
            Err(err) => warn!(
                self.logger,
                "Failed to fetch Boundary Node version: {}", err
            ),
        }
    }

    /// Start the current boundary node process
    fn ensure_boundary_node_running(&self, version: &ReplicaVersion) -> OrchestratorResult<()> {
        let mut process = self.process.lock().unwrap();

        if process.is_running() {
            return Ok(());
        }
        info!(self.logger, "Starting new boundary node process");

        let binary = self
            .ic_binary_dir
            .join("ic-boundary")
            .as_path()
            .display()
            .to_string();

        let domain_name = self
            .domain_name
            .as_ref()
            .ok_or_else(|| OrchestratorError::DomainNameMissingError(self.node_id))?;

        let env = env_file_reader::read_file("/opt/ic/share/ic-boundary.env").map_err(|e| {
            OrchestratorError::IoError("unable to read ic-boundary environment variables".into(), e)
        })?;

        let args = vec![
            format!("--tls-hostname={}", domain_name),
            format!(
                "--crypto-config={}",
                serde_json::to_string(&self.crypto_config)
                    .map_err(OrchestratorError::SerializeCryptoConfigError)?
            ),
        ];

        process
            .start(BoundaryNodeProcess {
                version: version.clone(),
                binary,
                args,
                env,
            })
            .map_err(|e| {
                OrchestratorError::IoError(
                    "Error when attempting to start new boundary node".into(),
                    e,
                )
            })
    }

    /// Stop the current boundary node process.
    fn ensure_boundary_node_stopped(&self) -> OrchestratorResult<()> {
        let mut process = self.process.lock().unwrap();
        if process.is_running() {
            return process.stop().map_err(|e| {
                OrchestratorError::IoError("Error when attempting to stop boundary node".into(), e)
            });
        }

        Ok(())
    }
}
