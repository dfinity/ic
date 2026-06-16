use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{ProcessRunner, SingleProcessRunner},
    processes::IcBoundaryProcess,
    registry_helper::RegistryHelper,
    upgrade::{start_ic_boundary, stop_ic_boundary},
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, warn};
use ic_types::{NodeId, ReplicaVersion};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub(crate) struct BoundaryNodeManager {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    process: Arc<Mutex<dyn ProcessRunner<IcBoundaryProcess>>>,
    ic_binary_dir: PathBuf,
    ic_boundary_env_file: PathBuf,
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
        ic_boundary_env_file: PathBuf,
        crypto_config: CryptoConfig,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            metrics,
            process: Arc::new(Mutex::new(SingleProcessRunner::new(logger.clone()))),
            ic_binary_dir,
            ic_boundary_env_file,
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
                            // let domain_name = Some(domain_name);

                            // stop ic-boundary when the domain name changes and start it again.
                            if Some(&domain_name) != self.domain_name.as_ref() {
                                if let Err(err) = self.ensure_ic_boundary_stopped() {
                                    warn!(self.logger, "Failed to stop Boundary Node: {}", err);
                                }
                                self.domain_name = Some(domain_name.clone());
                            }

                            // make sure the boundary node is running
                            if let Err(err) =
                                self.ensure_ic_boundary_running(&self.version, domain_name)
                            {
                                warn!(self.logger, "Failed to start Boundary Node: {}", err);
                            }
                        }
                        // BN should not be active when the node doesn't have a domain name
                        Ok(None) => {
                            warn!(
                                self.logger,
                                "There is no domain associated with the node, while this is a requirement for the API boundary node. Shutting ic-boundary down."
                            );
                            if let Err(err) = self.ensure_ic_boundary_stopped() {
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
                if let Err(err) = self.ensure_ic_boundary_stopped() {
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
    fn ensure_ic_boundary_running(
        &self,
        replica_version: &ReplicaVersion,
        domain_name: String,
    ) -> OrchestratorResult<()> {
        start_ic_boundary(
            &mut *self.process.lock().unwrap(),
            &self.ic_binary_dir,
            &self.ic_boundary_env_file,
            replica_version,
            domain_name,
            &self.crypto_config,
            &self.logger,
            &self.metrics,
        )
    }

    fn ensure_ic_boundary_stopped(&self) -> OrchestratorResult<()> {
        stop_ic_boundary(&mut *self.process.lock().unwrap())
    }
}
