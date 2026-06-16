use crate::{
    error::OrchestratorError, processes::IcBoundaryManager, registry_helper::RegistryHelper,
};
use ic_logger::{ReplicaLogger, warn};
use ic_types::{NodeId, ReplicaVersion};
use std::sync::{Arc, RwLock};

pub(crate) struct BoundaryNodeManager {
    registry: Arc<RegistryHelper>,
    process_manager: Arc<RwLock<IcBoundaryManager>>,
    version: ReplicaVersion,
    node_id: NodeId,
    logger: ReplicaLogger,
}

impl BoundaryNodeManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        process_manager: Arc<RwLock<IcBoundaryManager>>,
        version: ReplicaVersion,
        node_id: NodeId,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            process_manager,
            version,
            logger,
            node_id,
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
                    self.process_manager
                        .write()
                        .unwrap()
                        .ensure_ic_boundary_running_and_restarted_on_domain_change(
                            &self.version,
                            registry_version,
                        );
                }
            }
            // BN should not be active
            Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)) => {
                if let Err(err) = self.process_manager.write().unwrap().stop_ic_boundary() {
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
}
