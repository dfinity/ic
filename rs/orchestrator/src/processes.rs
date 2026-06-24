use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessRunner, SingleProcessRunner},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_types::{RegistryVersion, ReplicaVersion, SubnetId};
use nix::unistd::Pid;
use std::{collections::HashMap, ffi::OsString, path::PathBuf, sync::Arc};

// ---------------------------------------------------------------------------
// ReplicaProcess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ReplicaProcessConfig {
    pub ic_binary_dir: PathBuf,
    pub cup_path: PathBuf,
    pub replica_config_file: PathBuf,
}

pub(crate) struct ReplicaProcess {
    ic_binary_dir: PathBuf,
    replica_version: ReplicaVersion,
    cup_path: PathBuf,
    replica_config_file: PathBuf,
    subnet_id: SubnetId,
}

impl Process for ReplicaProcess {
    const NAME: &'static str = "replica";
    type Version = ReplicaVersion;
    type Config = ReplicaProcessConfig;
    type Args = (ReplicaVersion, SubnetId);

    fn build(
        config: &Self::Config,
        (replica_version, subnet_id): Self::Args,
    ) -> OrchestratorResult<Self> {
        Ok(Self {
            ic_binary_dir: config.ic_binary_dir.clone(),
            replica_version,
            cup_path: config.cup_path.clone(),
            replica_config_file: config.replica_config_file.clone(),
            subnet_id,
        })
    }

    fn get_version(&self) -> &Self::Version {
        &self.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--replica-version"),
            self.replica_version.to_string().into(),
            OsString::from("--config-file"),
            self.replica_config_file.clone().into(),
            OsString::from("--catch-up-package"),
            self.cup_path.clone().into(),
            OsString::from("--force-subnet"),
            self.subnet_id.to_string().into(),
        ]
    }
    fn get_env(&self) -> HashMap<OsString, OsString> {
        HashMap::new()
    }
}

// ---------------------------------------------------------------------------
// IcBoundaryProcess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct IcBoundaryProcessConfig {
    pub ic_binary_dir: PathBuf,
    pub ic_boundary_env_file: PathBuf,
    pub crypto_config: CryptoConfig,
}

pub(crate) struct IcBoundaryProcess {
    ic_binary_dir: PathBuf,
    replica_version: ReplicaVersion,
    domain_name: String,
    crypto_config: String,
    env: HashMap<OsString, OsString>,
}

impl Process for IcBoundaryProcess {
    const NAME: &'static str = "ic-boundary";
    type Version = ReplicaVersion;
    type Config = IcBoundaryProcessConfig;
    type Args = (ReplicaVersion, String);

    fn build(
        config: &Self::Config,
        (replica_version, domain_name): Self::Args,
    ) -> OrchestratorResult<Self> {
        let env = match env_file_reader::read_file(&config.ic_boundary_env_file) {
            Ok(env) => env
                .into_iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect(),
            Err(e) => {
                return Err(OrchestratorError::IoError(
                    "unable to read ic-boundary environment variables".to_string(),
                    e,
                ));
            }
        };
        let crypto_config = serde_json::to_string(&config.crypto_config)
            .map_err(OrchestratorError::SerializeCryptoConfigError)?;

        Ok(Self {
            ic_binary_dir: config.ic_binary_dir.clone(),
            replica_version,
            domain_name,
            crypto_config,
            env,
        })
    }

    fn get_version(&self) -> &Self::Version {
        &self.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--tls-hostname"),
            self.domain_name.clone().into(),
            OsString::from("--crypto-config"),
            self.crypto_config.clone().into(),
        ]
    }
    fn get_env(&self) -> HashMap<OsString, OsString> {
        self.env.clone()
    }
}

// ---------------------------------------------------------------------------
// IcGatewayProcess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct IcGatewayProcessConfig {
    pub ic_binary_dir: PathBuf,
    pub ic_gateway_env_file: PathBuf,
}

pub(crate) struct IcGatewayProcess {
    ic_binary_dir: PathBuf,
    replica_version: ReplicaVersion,
    env: HashMap<OsString, OsString>,
}

impl Process for IcGatewayProcess {
    const NAME: &'static str = "ic-gateway";
    type Version = ReplicaVersion;
    type Config = IcGatewayProcessConfig;
    type Args = ReplicaVersion;

    fn build(config: &Self::Config, replica_version: Self::Args) -> OrchestratorResult<Self> {
        let env = match env_file_reader::read_file(&config.ic_gateway_env_file) {
            Ok(env) => env
                .into_iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect(),
            Err(e) => {
                return Err(OrchestratorError::IoError(
                    "unable to read ic-gateway environment variables".to_string(),
                    e,
                ));
            }
        };

        Ok(Self {
            ic_binary_dir: config.ic_binary_dir.clone(),
            replica_version,
            env,
        })
    }

    fn get_version(&self) -> &Self::Version {
        &self.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![]
    }
    fn get_env(&self) -> HashMap<OsString, OsString> {
        self.env.clone()
    }
}

// ---------------------------------------------------------------------------
// ProcessManager<P>
//
// This struct offers common boilerplate functionality logic to ensure a process
// is running and to stop it, converting errors to [`OrchestratorError`], logging
// them, and updating metrics.
// ---------------------------------------------------------------------------

pub(crate) struct ProcessManager<P: Process> {
    process_runner: Box<dyn ProcessRunner<P> + Sync>,
    process_config: P::Config,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl<P: Process + Send + Sync + 'static> ProcessManager<P> {
    /// Used in tests to inject a mock ProcessRunner.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        process_runner: Box<dyn ProcessRunner<P> + Sync>,
        process_config: P::Config,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            process_runner,
            process_config,
            metrics,
            logger,
        }
    }

    pub(crate) fn new(
        process_config: P::Config,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let process_runner = Box::new(SingleProcessRunner::new(logger.clone()));
        Self {
            process_config,
            process_runner,
            metrics,
            logger,
        }
    }

    pub(crate) fn ensure_running(&mut self, args: P::Args) -> OrchestratorResult<()> {
        if self.process_runner.is_running() {
            return Ok(());
        }

        let process = P::build(&self.process_config, args)?;
        info!(self.logger, "Starting new {} process", P::NAME);
        self.metrics
            .processes_start_attempts
            .with_label_values(&[P::NAME])
            .inc();
        self.process_runner.start(process).map_err(|e| {
            OrchestratorError::IoError(
                format!("Error when attempting to start {} process", P::NAME),
                e,
            )
        })
    }

    pub(crate) fn stop(&mut self) -> OrchestratorResult<()> {
        if !self.process_runner.is_running() {
            return Ok(());
        }

        info!(self.logger, "Stopping {} process", P::NAME);
        self.metrics
            .processes_stop_attempts
            .with_label_values(&[P::NAME])
            .inc();
        self.process_runner.stop().map_err(|e| {
            OrchestratorError::IoError(
                format!("Error when attempting to stop the {} process", P::NAME),
                e,
            )
        })
    }
}

// ---------------------------------------------------------------------------
// IcBoundaryManager
//
// Wrapper around ProcessManager<IcBoundaryProcess> which contains additional
// logic to stop and restart the process when the node's domain name changes
// in the registry.
// ---------------------------------------------------------------------------

pub(crate) struct IcBoundaryManager {
    inner: ProcessManager<IcBoundaryProcess>,
    registry: Arc<RegistryHelper>,
    current_domain_name: Option<String>,
}

impl IcBoundaryManager {
    pub(crate) fn new(
        config: <IcBoundaryProcess as Process>::Config,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let inner = ProcessManager::new(config, metrics, logger);
        Self {
            inner,
            registry,
            current_domain_name: None,
        }
    }

    // Used in tests to inject a mock ProcessManager.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        inner: ProcessManager<IcBoundaryProcess>,
        registry: Arc<RegistryHelper>,
    ) -> Self {
        Self {
            inner,
            registry,
            current_domain_name: None,
        }
    }

    pub(crate) fn ensure_ic_boundary_running_and_restarted_on_domain_change(
        &mut self,
        replica_version: ReplicaVersion,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        let domain_name = match self.registry.get_node_domain_name(registry_version) {
            Ok(domain_name) => domain_name,
            Err(err @ OrchestratorError::DomainNameMissingError(_, _)) => {
                // ic-boundary should not start when the node doesn't have a domain name
                self.inner.stop()?;

                // Only clear the current domain name if we successfully stopped ic-boundary, so
                // that we correctly detect we should first retry to stop it in case we get a new
                // domain name in a next call.
                self.current_domain_name = None;
                return Err(err);
            }
            Err(err) => return Err(err),
        };

        // stop ic-boundary when the domain name changes and start it again.
        if Some(&domain_name) != self.current_domain_name.as_ref() {
            self.inner.stop()?;
        }

        // make sure ic-boundary is running
        self.inner
            .ensure_running((replica_version, domain_name.clone()))?;

        // Only update the current domain name if we performed the operations above successfully,
        // so that we can retry on the next call if not.
        self.current_domain_name = Some(domain_name);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> OrchestratorResult<()> {
        self.inner.stop()
    }
}

// ---------------------------------------------------------------------------
// MultipleProcessesManager
//
// This struct manages all processes that the upgrade loop is responsible for,
// providing a single entry point for starting and stopping them according to
// the node's configuration in the registry.
// ---------------------------------------------------------------------------

/// Whether the orchestrator is currently allowed to actually launch
/// `ic-gateway`. CloudEngine nodes *should* run `ic-gateway`, but the launch
/// is gated off for now while the rollout is being prepared. To trigger it
/// later, flip this to `true` (and re-enable the `cloud_engine_ic_gateway_test`
/// system test by removing its `manual` tag).
const IC_GATEWAY_LAUNCH_ENABLED: bool = false;

pub(crate) struct MultipleProcessesManager {
    replica_manager: ProcessManager<ReplicaProcess>,
    ic_gateway_manager: ProcessManager<IcGatewayProcess>,
    registry: Arc<RegistryHelper>,
    /// Whether this manager is allowed to actually launch `ic-gateway`.
    /// Sourced from [`IC_GATEWAY_LAUNCH_ENABLED`] in production; injected by
    /// tests so they can exercise both gate states.
    ic_gateway_launch_enabled: bool,
}

impl MultipleProcessesManager {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        replica_manager: ProcessManager<ReplicaProcess>,
        ic_gateway_manager: ProcessManager<IcGatewayProcess>,
        registry: Arc<RegistryHelper>,
        ic_gateway_launch_enabled: bool,
    ) -> Self {
        Self {
            replica_manager,
            ic_gateway_manager,
            registry,
            ic_gateway_launch_enabled,
        }
    }

    pub(crate) fn new(
        replica_process_config: ReplicaProcessConfig,
        ic_gateway_process_config: IcGatewayProcessConfig,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let replica_manager =
            ProcessManager::new(replica_process_config, metrics.clone(), logger.clone());
        let ic_gateway_manager = ProcessManager::new(ic_gateway_process_config, metrics, logger);

        Self {
            replica_manager,
            ic_gateway_manager,
            registry,
            ic_gateway_launch_enabled: IC_GATEWAY_LAUNCH_ENABLED,
        }
    }

    // Used in tests to assert the state of the managed processes.
    #[cfg(test)]
    pub(crate) fn is_replica_running(&self) -> bool {
        self.replica_manager.process_runner.is_running()
    }

    // Used in tests to assert the state of the managed processes.
    #[cfg(test)]
    pub(crate) fn is_ic_gateway_running(&self) -> bool {
        self.ic_gateway_manager.process_runner.is_running()
    }

    pub(crate) fn get_replica_pid(&self) -> Option<Pid> {
        self.replica_manager.process_runner.get_pid()
    }

    pub(crate) fn get_ic_gateway_pid(&self) -> Option<Pid> {
        self.ic_gateway_manager.process_runner.get_pid()
    }

    /// Start all processes appropriate for this node.
    ///
    /// Always starts the replica.  For cloud-engine subnet nodes it also
    /// starts ic-gateway.
    pub(crate) fn start_all(
        &mut self,
        replica_version: ReplicaVersion,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        self.replica_manager
            .ensure_running((replica_version.clone(), subnet_id))?;

        // Cloud-engine nodes run ic-gateway as a sidecar, but only once the
        // launch is enabled (see `IC_GATEWAY_LAUNCH_ENABLED`). Until then,
        // ignore it.
        if self.ic_gateway_launch_enabled {
            match self.registry.get_subnet_type(subnet_id, registry_version)? {
                None
                | Some(SubnetType::Unspecified)
                | Some(SubnetType::Application)
                | Some(SubnetType::System)
                | Some(SubnetType::VerifiedApplication) => {
                    self.ic_gateway_manager.stop()?;
                }
                Some(SubnetType::CloudEngine) => {
                    self.ic_gateway_manager.ensure_running(replica_version)?;
                }
            }
        }

        Ok(())
    }

    /// Stop the replica process.
    pub(crate) fn stop_replica(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop()
    }

    /// Stop every managed process.
    pub(crate) fn stop_all(&mut self) -> OrchestratorResult<()> {
        if self.ic_gateway_launch_enabled {
            self.ic_gateway_manager.stop()?;
        }
        self.replica_manager.stop()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node_operator::NodeRecord;
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::NODE_1;
    use std::{path::Path, sync::Mutex};
    use tempfile::tempdir;

    const REPLICA_VERSION: &str = "replica_version_0.1";

    /// Counters recorded by [`RecordingRunner`], so tests can assert whether
    /// (and how often) the managed process was started/stopped.
    #[derive(Default)]
    struct RunnerLog {
        running: bool,
        starts: usize,
        stops: usize,
    }

    /// A `ProcessRunner` fake that records start/stop calls instead of spawning.
    struct RecordingRunner {
        log: Arc<Mutex<RunnerLog>>,
    }

    impl<P: Process> ProcessRunner<P> for RecordingRunner {
        fn start(&mut self, _process: P) -> std::io::Result<()> {
            let mut log = self.log.lock().unwrap();
            log.running = true;
            log.starts += 1;
            Ok(())
        }

        fn stop(&mut self) -> std::io::Result<()> {
            let mut log = self.log.lock().unwrap();
            log.running = false;
            log.stops += 1;
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.log.lock().unwrap().running
        }

        fn get_pid(&self) -> Option<Pid> {
            self.log
                .lock()
                .unwrap()
                .running
                .then_some(Pid::from_raw(12345))
        }
    }

    /// Builds a registry whose node record for `NODE_1` carries the given domain
    /// at each listed registry version (`None` means "no domain").
    fn registry_with_node_domains(domains: &[(u64, Option<&str>)]) -> Arc<RegistryHelper> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        for &(version, domain) in domains {
            data_provider
                .add(
                    &make_node_record_key(NODE_1),
                    RegistryVersion::from(version),
                    Some(NodeRecord {
                        domain: domain.map(str::to_string),
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();
        Arc::new(RegistryHelper::new(NODE_1, registry_client, no_op_logger()))
    }

    /// Builds an [`IcBoundaryManager`] backed by a [`RecordingRunner`], returning
    /// the manager and a handle to the runner's log.
    fn ic_boundary_manager_for_test(
        registry: Arc<RegistryHelper>,
        dir: &Path,
    ) -> (IcBoundaryManager, Arc<Mutex<RunnerLog>>) {
        let log = Arc::new(Mutex::new(RunnerLog::default()));
        let runner = Box::new(RecordingRunner { log: log.clone() });
        let env_file = dir.join("ic-boundary.env");
        std::fs::write(&env_file, b"TEST_KEY=TEST_VALUE").unwrap();
        let config = IcBoundaryProcessConfig {
            ic_binary_dir: dir.to_path_buf(),
            ic_boundary_env_file: env_file,
            crypto_config: CryptoConfig::default(),
        };
        let inner = ProcessManager::new_for_test(
            runner,
            config,
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        );
        let manager = IcBoundaryManager::new_for_test(inner, registry);
        (manager, log)
    }

    fn ensure(manager: &mut IcBoundaryManager, registry_version: u64) -> OrchestratorResult<()> {
        manager.ensure_ic_boundary_running_and_restarted_on_domain_change(
            ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
            RegistryVersion::from(registry_version),
        )
    }

    #[test]
    fn ic_boundary_not_started_when_node_has_no_domain() {
        let dir = tempdir().unwrap();
        let registry = registry_with_node_domains(&[(1, None)]);
        let (mut manager, log) = ic_boundary_manager_for_test(registry, dir.path());

        assert_matches!(
            ensure(&mut manager, 1),
            Err(OrchestratorError::DomainNameMissingError(_, _))
        );

        let log = log.lock().unwrap();
        assert!(!log.running);
        assert_eq!(log.starts, 0);
        assert_eq!(log.stops, 0);
        assert_eq!(manager.current_domain_name, None);
    }

    #[test]
    fn ic_boundary_starts_when_node_has_domain() {
        let dir = tempdir().unwrap();
        let registry = registry_with_node_domains(&[(1, Some("api1.example.com"))]);
        let (mut manager, log) = ic_boundary_manager_for_test(registry, dir.path());

        ensure(&mut manager, 1).expect("ic-boundary should have started successfully");

        let log = log.lock().unwrap();
        assert!(log.running);
        assert_eq!(log.starts, 1);
        assert_eq!(log.stops, 0);
        assert_eq!(
            manager.current_domain_name.as_deref(),
            Some("api1.example.com")
        );
    }

    #[test]
    fn ic_boundary_not_restarted_when_domain_unchanged() {
        let dir = tempdir().unwrap();
        let registry = registry_with_node_domains(&[(1, Some("api1.example.com"))]);
        let (mut manager, log) = ic_boundary_manager_for_test(registry, dir.path());

        ensure(&mut manager, 1).expect("ic-boundary should have started successfully");
        ensure(&mut manager, 1).expect("ic-boundary should have started successfully");

        let log = log.lock().unwrap();
        assert!(log.running);
        // Started once on the first call; the second call must not restart it.
        assert_eq!(log.starts, 1);
        assert_eq!(log.stops, 0);
        assert_eq!(
            manager.current_domain_name.as_deref(),
            Some("api1.example.com")
        );
    }

    #[test]
    fn ic_boundary_restarted_when_domain_changes() {
        let dir = tempdir().unwrap();
        let registry = registry_with_node_domains(&[
            (1, Some("api1.example.com")),
            (2, Some("api2.example.com")),
        ]);
        let (mut manager, log) = ic_boundary_manager_for_test(registry, dir.path());

        ensure(&mut manager, 1).expect("ic-boundary should have started successfully");
        ensure(&mut manager, 2).expect("ic-boundary should have started successfully");

        let log = log.lock().unwrap();
        assert!(log.running);
        // Restart on domain change: stopped once, started twice.
        assert_eq!(log.starts, 2);
        assert_eq!(log.stops, 1);
        assert_eq!(
            manager.current_domain_name.as_deref(),
            Some("api2.example.com")
        );
    }

    #[test]
    fn ic_boundary_stopped_when_domain_is_deleted() {
        let dir = tempdir().unwrap();
        let registry = registry_with_node_domains(&[(1, Some("api1.example.com")), (2, None)]);
        let (mut manager, log) = ic_boundary_manager_for_test(registry, dir.path());

        // Running with a domain ...
        ensure(&mut manager, 1).expect("ic-boundary should have started successfully");
        assert!(log.lock().unwrap().running);

        // ... then the domain is removed: ic-boundary must be stopped.
        assert_matches!(
            ensure(&mut manager, 2),
            Err(OrchestratorError::DomainNameMissingError(_, _))
        );

        let log = log.lock().unwrap();
        assert!(!log.running);
        assert_eq!(log.starts, 1);
        assert_eq!(log.stops, 1);
        assert_eq!(manager.current_domain_name, None);
    }
}
