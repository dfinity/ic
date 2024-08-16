use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessManager},
    registry_helper::RegistryHelper,
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{NodeId, ReplicaVersion};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct BoundaryNodeProcess {
    version: ReplicaVersion,
    binary: String,
    args: Vec<String>,
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
}

pub(crate) struct BoundaryNodeManager {
    registry: Arc<RegistryHelper>,
    _metrics: Arc<OrchestratorMetrics>,
    process: Arc<Mutex<ProcessManager<BoundaryNodeProcess>>>,
    ic_binary_dir: PathBuf,
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
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            _metrics: metrics,
            process: Arc::new(Mutex::new(ProcessManager::new(
                logger.clone().inner_logger.root,
            ))),
            ic_binary_dir,
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
                            warn!(self.logger, "There is no domain associated with the node, while this is a requirement for the API boundary node. Shutting ic-boundary down.");
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

        // TODO: Should these values be settable via config?
        let args = vec![
            format!("--hostname={}", domain_name),
            format!("--http-port=80"),
            format!("--https-port=443"),
            format!("--tls-cert-path=/var/lib/ic/data/ic-boundary-tls.crt"),
            format!("--tls-pkey-path=/var/lib/ic/data/ic-boundary-tls.key"),
            format!("--acme-credentials-path=/var/lib/ic/data/ic-boundary-acme.json"),
            format!("--disable-registry-replicator"),
            format!("--local-store-path=/var/lib/ic/data/ic_registry_local_store"),
            format!("--log-journald"),
            format!("--metrics-addr=[::]:9324"),
            format!("--rate-limit-per-second-per-subnet=1000"),
            format!("--bouncer-enable"),
            format!("--bouncer-ratelimit=600"),
            format!("--bouncer-burst-size=1200"),
            format!("--bouncer-ban-seconds=300"),
            format!("--bouncer-max-buckets=30000"),
            format!("--bouncer-bucket-ttl=60"),
            format!("--cache-size-bytes=1073741824"),
            format!("--cache-max-item-size-bytes=10485760"),
            format!("--cache-ttl-seconds=1"),
        ];

        process
            .start(BoundaryNodeProcess {
                version: version.clone(),
                binary,
                args,
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
