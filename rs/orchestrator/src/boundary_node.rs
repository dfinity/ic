use crate::{
    error::{OrchestratorError, OrchestratorResult},
    process_manager::Process,
    processes::{IcBoundaryProcess, ProcessManager},
    registry_helper::RegistryHelper,
};
use ic_logger::{ReplicaLogger, warn};
use ic_types::{NodeId, RegistryVersion, ReplicaVersion};
use std::sync::Arc;

pub(crate) struct BoundaryNodeManager {
    registry: Arc<RegistryHelper>,
    process_manager: ProcessManager<IcBoundaryProcess>,
    version: ReplicaVersion,
    node_id: NodeId,
    logger: ReplicaLogger,
}

impl BoundaryNodeManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        process_manager: ProcessManager<IcBoundaryProcess>,
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
                } else if let Err(err) = self.ensure_ic_boundary_running(registry_version) {
                    warn!(
                        self.logger,
                        "Failed to ensure {} is running: {}",
                        IcBoundaryProcess::NAME,
                        err
                    );
                }
            }
            // BN should not be active
            Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)) => {
                if let Err(err) = self.process_manager.stop() {
                    warn!(
                        self.logger,
                        "Failed to stop {}: {}",
                        IcBoundaryProcess::NAME,
                        err
                    );
                }
            }
            // Failing to read the registry
            Err(err) => warn!(
                self.logger,
                "Failed to fetch API Boundary Node version: {}", err
            ),
        }
    }

    /// Ensures ic-boundary is running with the node's domain name, restarting it if the domain
    /// name changed. Stops ic-boundary if the node doesn't have a domain name.
    fn ensure_ic_boundary_running(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        match self.registry.get_node_domain_name(registry_version) {
            Ok(domain_name) => self
                .process_manager
                .ensure_running((self.version.clone(), domain_name)),
            Err(OrchestratorError::DomainNameMissingError(_, _)) => {
                // ic-boundary should not run when the node doesn't have a domain name
                self.process_manager.stop()
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metrics::OrchestratorMetrics,
        process_manager::fake::{FakeProcessRunner, FakeRunnerLog},
        processes::IcBoundaryProcessConfig,
    };
    use ic_config::crypto::CryptoConfig;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node_operator::NodeRecord;
    use ic_registry_keys::{make_api_boundary_node_record_key, make_node_record_key};
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::NODE_1;
    use std::sync::Mutex;
    use tempfile::{TempDir, tempdir};

    const REPLICA_VERSION: &str = "replica_version_0.1";

    struct TestSetup {
        manager: BoundaryNodeManager,
        log: Arc<Mutex<FakeRunnerLog<IcBoundaryProcess>>>,
        data_provider: Arc<ProtoRegistryDataProvider>,
        registry_client: Arc<FakeRegistryClient>,
        _dir: TempDir,
    }

    impl TestSetup {
        /// Builds a [`BoundaryNodeManager`] for `NODE_1`, an API boundary node running
        /// `REPLICA_VERSION`, backed by a [`FakeProcessRunner`].
        fn new() -> Self {
            let data_provider = Arc::new(ProtoRegistryDataProvider::new());
            data_provider
                .add(
                    &make_api_boundary_node_record_key(NODE_1),
                    RegistryVersion::from(1),
                    Some(ApiBoundaryNodeRecord {
                        version: REPLICA_VERSION.to_string(),
                    }),
                )
                .unwrap();
            let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
            let registry = Arc::new(RegistryHelper::new(
                NODE_1,
                registry_client.clone(),
                no_op_logger(),
            ));

            let dir = tempdir().unwrap();
            let env_file = dir.path().join("ic-boundary.env");
            std::fs::write(&env_file, b"TEST_KEY=TEST_VALUE").unwrap();
            let config = IcBoundaryProcessConfig {
                ic_binary_dir: dir.path().to_path_buf(),
                ic_boundary_env_file: env_file,
                crypto_config: CryptoConfig::default(),
            };

            let runner = FakeProcessRunner::new();
            let log = runner.log();
            let process_manager = ProcessManager::new_for_test(
                Box::new(runner),
                config,
                Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
                no_op_logger(),
            );
            let manager = BoundaryNodeManager::new(
                registry,
                process_manager,
                ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
                NODE_1,
                no_op_logger(),
            );

            Self {
                manager,
                log,
                data_provider,
                registry_client,
                _dir: dir,
            }
        }

        /// Sets the node's domain at the given registry version (`None` means "no domain") and
        /// makes it the latest version.
        fn set_domain(&self, version: u64, domain: Option<&str>) {
            self.data_provider
                .add(
                    &make_node_record_key(NODE_1),
                    RegistryVersion::from(version),
                    Some(NodeRecord {
                        domain: domain.map(str::to_string),
                        ..Default::default()
                    }),
                )
                .unwrap();
            self.registry_client.update_to_latest_version();
        }

        /// Returns `(starts, stops, domain of the running ic-boundary)`.
        fn state(&self) -> (usize, usize, Option<String>) {
            let log = self.log.lock().unwrap();
            let domain = log
                .process
                .as_ref()
                .map(|process| process.domain_name().to_string());
            (log.starts, log.stops, domain)
        }
    }

    #[tokio::test]
    async fn ic_boundary_not_started_when_node_has_no_domain() {
        let mut setup = TestSetup::new();
        setup.set_domain(2, None);

        setup.manager.check().await;

        assert_eq!(setup.state(), (0, 0, None));
    }

    #[tokio::test]
    async fn ic_boundary_starts_when_node_has_domain() {
        let mut setup = TestSetup::new();
        setup.set_domain(2, Some("api1.example.com"));

        setup.manager.check().await;

        assert_eq!(setup.state(), (1, 0, Some("api1.example.com".to_string())));
    }

    #[tokio::test]
    async fn ic_boundary_not_restarted_when_domain_unchanged() {
        let mut setup = TestSetup::new();
        setup.set_domain(2, Some("api1.example.com"));

        setup.manager.check().await;
        assert_eq!(setup.state(), (1, 0, Some("api1.example.com".to_string())));

        setup.manager.check().await;
        // Started once on the first call; the second call must not restart it.
        assert_eq!(setup.state(), (1, 0, Some("api1.example.com".to_string())));
    }

    #[tokio::test]
    async fn ic_boundary_restarted_when_domain_changes() {
        let mut setup = TestSetup::new();
        setup.set_domain(2, Some("api1.example.com"));
        setup.manager.check().await;

        setup.set_domain(3, Some("api2.example.com"));
        setup.manager.check().await;

        // Restart on domain change: stopped once, started twice.
        assert_eq!(setup.state(), (2, 1, Some("api2.example.com".to_string())));
    }

    #[tokio::test]
    async fn ic_boundary_stopped_when_domain_is_deleted() {
        let mut setup = TestSetup::new();
        setup.set_domain(2, Some("api1.example.com"));
        setup.manager.check().await;
        assert_eq!(setup.state(), (1, 0, Some("api1.example.com".to_string())));

        setup.set_domain(3, None);
        setup.manager.check().await;
        assert_eq!(setup.state(), (1, 1, None));

        setup.set_domain(4, Some("api1.example.com"));
        setup.manager.check().await;
        assert_eq!(setup.state(), (2, 1, Some("api1.example.com".to_string())));
    }
}
