use crate::{
    cloud_engine::GatewayConfig,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessRunner, SingleProcessRunner},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info};
use ic_types::{RegistryVersion, ReplicaVersion, SubnetId};
use nix::unistd::Pid;
use std::{
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, RwLock},
};

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
        let env = match crate::env_file::read_file(&config.ic_boundary_env_file) {
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
    /// Where `ic-gateway` keeps its ACME account and the certificates it issues.
    pub acme_cache_dir: PathBuf,
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
    type Args = (ReplicaVersion, GatewayConfig);

    fn build(
        config: &Self::Config,
        (replica_version, gateway_config): Self::Args,
    ) -> OrchestratorResult<Self> {
        let mut env: HashMap<OsString, OsString> =
            match crate::env_file::read_file(&config.ic_gateway_env_file) {
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

        // `ic-gateway` writes its ACME account and certificates here.
        std::fs::create_dir_all(&config.acme_cache_dir).map_err(|e| {
            OrchestratorError::IoError(format!("Failed to create {:?}", config.acme_cache_dir), e)
        })?;

        // The shipped file only carries policy; the engine's own values, the two
        // credentials among them, override it.
        env.extend(
            gateway_config
                .env_overlay(&config.acme_cache_dir)?
                .into_iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        );

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
// IcGatewayManager
//
// Wrapper around ProcessManager<IcGatewayProcess> which stops and restarts the
// process when the engine configuration changes.
// ---------------------------------------------------------------------------

pub(crate) struct IcGatewayManager {
    inner: ProcessManager<IcGatewayProcess>,
    current_config: Option<GatewayConfig>,
}

impl IcGatewayManager {
    pub(crate) fn new(
        config: <IcGatewayProcess as Process>::Config,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            inner: ProcessManager::new(config, metrics, logger),
            current_config: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(inner: ProcessManager<IcGatewayProcess>) -> Self {
        Self {
            inner,
            current_config: None,
        }
    }

    /// Runs `ic-gateway` with `gateway_config`, restarting it when the config
    /// changed. `None` means the engine configuration is not (yet) known, in
    /// which case `ic-gateway` must not run at all: it terminates TLS for the
    /// engine and has nothing to serve without it.
    pub(crate) fn ensure_running_and_restarted_on_config_change(
        &mut self,
        replica_version: ReplicaVersion,
        gateway_config: Option<GatewayConfig>,
    ) -> OrchestratorResult<()> {
        let Some(gateway_config) = gateway_config else {
            return self.stop();
        };

        // Restart only on a change we actually observed: with nothing applied
        // yet there is nothing to compare against, and `ensure_running` is a
        // no-op when the process is already up. The explicit stop is needed
        // because the process runner only compares versions, so an
        // environment-only change would otherwise not take effect.
        if self.current_config.is_some() && self.current_config.as_ref() != Some(&gateway_config) {
            self.inner.stop()?;
            // `stop` only signals the process. While the old process is still
            // draining, neither start nor record the new config: the next call
            // still sees the old config, signals the process again (in case it
            // ignored the first SIGTERM), and starts the new one once the old
            // one is gone.
            if self.inner.process_runner.is_running() {
                return Ok(());
            }
        }

        self.inner
            .ensure_running((replica_version, gateway_config.clone()))?;

        // Only remember the config once it was applied, so that a failure above
        // is retried on the next call.
        self.current_config = Some(gateway_config);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> OrchestratorResult<()> {
        self.inner.stop()?;
        // `stop` only signals the process: forget the config only once the
        // process is actually gone, so that one still draining keeps being
        // signalled by the calls that follow.
        if !self.inner.process_runner.is_running() {
            self.current_config = None;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MultipleProcessesManager
//
// This struct manages all processes that the upgrade loop is responsible for,
// providing a single entry point for starting and stopping them according to
// the node's configuration in the registry.
// ---------------------------------------------------------------------------

pub(crate) struct MultipleProcessesManager {
    replica_manager: ProcessManager<ReplicaProcess>,
    ic_gateway_manager: IcGatewayManager,
    /// Engine configuration published by [`crate::cloud_engine`].
    gateway_config: Arc<RwLock<Option<GatewayConfig>>>,
    registry: Arc<RegistryHelper>,
}

impl MultipleProcessesManager {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        replica_manager: ProcessManager<ReplicaProcess>,
        ic_gateway_manager: IcGatewayManager,
        gateway_config: Arc<RwLock<Option<GatewayConfig>>>,
        registry: Arc<RegistryHelper>,
    ) -> Self {
        Self {
            replica_manager,
            ic_gateway_manager,
            gateway_config,
            registry,
        }
    }

    pub(crate) fn new(
        replica_process_config: ReplicaProcessConfig,
        ic_gateway_process_config: IcGatewayProcessConfig,
        gateway_config: Arc<RwLock<Option<GatewayConfig>>>,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let replica_manager =
            ProcessManager::new(replica_process_config, metrics.clone(), logger.clone());
        let ic_gateway_manager = IcGatewayManager::new(ic_gateway_process_config, metrics, logger);

        Self {
            replica_manager,
            ic_gateway_manager,
            gateway_config,
            registry,
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
        self.ic_gateway_manager.inner.process_runner.is_running()
    }

    pub(crate) fn get_replica_pid(&self) -> Option<Pid> {
        self.replica_manager.process_runner.get_pid()
    }

    pub(crate) fn get_ic_gateway_pid(&self) -> Option<Pid> {
        self.ic_gateway_manager.inner.process_runner.get_pid()
    }

    /// Start all processes appropriate for this node.
    /// If a process fails to start, continue starting the others and return the first error.
    ///
    /// Always starts the replica.  For cloud-engine subnet nodes it also
    /// starts ic-gateway.
    pub(crate) fn start_all(
        &mut self,
        replica_version: ReplicaVersion,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        let mut result = Ok(());
        result = result.and(
            self.replica_manager
                .ensure_running((replica_version.clone(), subnet_id)),
        );

        // Cloud-engine nodes run ic-gateway as a sidecar.
        result = result.and(
            if self
                .registry
                .is_cloud_engine_subnet(subnet_id, registry_version)?
            {
                let gateway_config = self.gateway_config.read().unwrap().clone();
                self.ic_gateway_manager
                    .ensure_running_and_restarted_on_config_change(replica_version, gateway_config)
            } else {
                self.ic_gateway_manager.stop()
            },
        );

        result
    }

    /// Stop the replica process.
    pub(crate) fn stop_replica(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop()
    }

    /// Stop every managed process in reverse order of startup
    /// If a process fails to stop, continue stopping the others and return the first error.
    pub(crate) fn stop_all(&mut self) -> OrchestratorResult<()> {
        let mut result = Ok(());
        result = result.and(self.ic_gateway_manager.stop());
        result = result.and(self.replica_manager.stop());

        result
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

    /// Like [`RecordingRunner`], but `stop` only records the signal and leaves
    /// the process running, the way SIGTERM leaves a real process draining
    /// until it actually exits. Tests simulate the exit by clearing `running`.
    struct DrainingRunner {
        log: Arc<Mutex<RunnerLog>>,
    }

    impl<P: Process> ProcessRunner<P> for DrainingRunner {
        fn start(&mut self, _process: P) -> std::io::Result<()> {
            let mut log = self.log.lock().unwrap();
            log.running = true;
            log.starts += 1;
            Ok(())
        }

        fn stop(&mut self) -> std::io::Result<()> {
            self.log.lock().unwrap().stops += 1;
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

    /// Builds an [`IcGatewayManager`] backed by a [`RecordingRunner`], returning
    /// the manager and a handle to the runner's log.
    fn ic_gateway_manager_for_test(dir: &Path) -> (IcGatewayManager, Arc<Mutex<RunnerLog>>) {
        let log = Arc::new(Mutex::new(RunnerLog::default()));
        let runner = Box::new(RecordingRunner { log: log.clone() });
        ic_gateway_manager_with_runner(dir, runner, log)
    }

    fn ic_gateway_manager_with_runner(
        dir: &Path,
        runner: Box<dyn ProcessRunner<IcGatewayProcess> + Sync>,
        log: Arc<Mutex<RunnerLog>>,
    ) -> (IcGatewayManager, Arc<Mutex<RunnerLog>>) {
        let env_file = dir.join("ic-gateway.env");
        std::fs::write(&env_file, b"LISTEN_PLAIN=[::]:80").unwrap();
        let config = IcGatewayProcessConfig {
            ic_binary_dir: dir.to_path_buf(),
            ic_gateway_env_file: env_file,
            acme_cache_dir: dir.join("acme"),
        };
        let inner = ProcessManager::new_for_test(
            runner,
            config,
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        );

        (IcGatewayManager::new_for_test(inner), log)
    }

    fn ensure_gateway(
        manager: &mut IcGatewayManager,
        gateway_config: Option<GatewayConfig>,
    ) -> OrchestratorResult<()> {
        manager.ensure_running_and_restarted_on_config_change(
            ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
            gateway_config,
        )
    }

    #[test]
    fn ic_gateway_not_started_without_a_config() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());

        // It terminates TLS for the engine, so it has nothing to serve without
        // the engine's configuration.
        ensure_gateway(&mut manager, None).expect("nothing to do should not fail");

        let log = log.lock().unwrap();
        assert!(!log.running);
        assert_eq!(log.starts, 0);
    }

    #[test]
    fn ic_gateway_starts_once_the_config_is_known() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());

        ensure_gateway(&mut manager, None).unwrap();
        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("engine.example.com")),
        )
        .unwrap();

        let log = log.lock().unwrap();
        assert!(log.running);
        assert_eq!(log.starts, 1);
        assert_eq!(log.stops, 0);
    }

    #[test]
    fn ic_gateway_not_restarted_when_config_unchanged() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());
        let config = GatewayConfig::for_test("engine.example.com");

        ensure_gateway(&mut manager, Some(config.clone())).unwrap();
        ensure_gateway(&mut manager, Some(config)).unwrap();

        let log = log.lock().unwrap();
        assert!(log.running);
        assert_eq!(log.starts, 1);
        assert_eq!(log.stops, 0);
    }

    #[test]
    fn ic_gateway_restarted_when_config_changes() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());

        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("one.example.com")),
        )
        .unwrap();
        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("two.example.com")),
        )
        .unwrap();

        let log = log.lock().unwrap();
        assert!(log.running);
        assert_eq!(log.starts, 2);
        assert_eq!(log.stops, 1);
    }

    #[test]
    fn ic_gateway_config_change_waits_for_the_old_process_to_exit() {
        let dir = tempdir().unwrap();
        let log = Arc::new(Mutex::new(RunnerLog::default()));
        let runner = Box::new(DrainingRunner { log: log.clone() });
        let (mut manager, log) = ic_gateway_manager_with_runner(dir.path(), runner, log);

        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("one.example.com")),
        )
        .unwrap();
        assert_eq!(log.lock().unwrap().starts, 1);

        // The config changes, but the old process only gets signalled and keeps
        // draining: the new one must not start (the port is still taken), and
        // the new config must not count as applied.
        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("two.example.com")),
        )
        .unwrap();
        {
            let log = log.lock().unwrap();
            assert_eq!(log.stops, 1);
            assert_eq!(log.starts, 1);
        }

        // Still draining on the next call: it has to be signalled again, in
        // case it ignored the first SIGTERM.
        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("two.example.com")),
        )
        .unwrap();
        assert_eq!(log.lock().unwrap().stops, 2);

        // Once the old process exited, the next call starts the new one.
        log.lock().unwrap().running = false;
        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("two.example.com")),
        )
        .unwrap();
        let log = log.lock().unwrap();
        assert!(log.running);
        assert_eq!(log.starts, 2);
    }

    #[test]
    fn ic_gateway_stopped_when_the_config_is_withdrawn() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());

        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("engine.example.com")),
        )
        .unwrap();
        assert!(log.lock().unwrap().running);

        ensure_gateway(&mut manager, None).unwrap();

        let log = log.lock().unwrap();
        assert!(!log.running);
        assert_eq!(log.stops, 1);
    }

    #[test]
    fn ic_gateway_acme_cache_is_created() {
        let dir = tempdir().unwrap();
        let (mut manager, _log) = ic_gateway_manager_for_test(dir.path());

        ensure_gateway(
            &mut manager,
            Some(GatewayConfig::for_test("engine.example.com")),
        )
        .unwrap();

        // The issued certificate's private key lands here.
        assert!(dir.path().join("acme").is_dir());
    }

    #[test]
    fn ic_gateway_credentials_never_reach_the_argument_list() {
        let dir = tempdir().unwrap();
        let config = GatewayConfig::for_test("engine.example.com");
        let process = IcGatewayProcess::build(
            &IcGatewayProcessConfig {
                ic_binary_dir: dir.path().to_path_buf(),
                ic_gateway_env_file: {
                    let env_file = dir.path().join("ic-gateway.env");
                    std::fs::write(&env_file, b"LISTEN_PLAIN=[::]:80").unwrap();
                    env_file
                },
                acme_cache_dir: dir.path().join("acme"),
            },
            (
                ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
                config.clone(),
            ),
        )
        .unwrap();

        // Arguments are logged by the process runner and are world-readable via
        // /proc/<pid>/cmdline; the environment is neither.
        let args = format!("{:?}", process.get_args());
        assert!(!args.contains(&config.dns_api_key), "{args}");
        assert!(!args.contains(&config.acme_account.key_pkcs8), "{args}");

        let env = process.get_env();
        assert_eq!(
            env.get(&OsString::from("ACME_DNS_IC_DNS_LB_TOKEN")),
            Some(&OsString::from(config.dns_api_key.clone()))
        );
        // The shipped file stays the base layer.
        assert_eq!(
            env.get(&OsString::from("LISTEN_PLAIN")),
            Some(&OsString::from("[::]:80"))
        );
        assert_eq!(
            env.get(&OsString::from("DOMAIN")),
            Some(&OsString::from("engine.example.com"))
        );
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
