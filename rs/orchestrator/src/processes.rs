use crate::{
    cloud_engine::config::EngineConfig,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{
        Process, ProcessObserver, ProcessRunner, RestartDecision, SingleProcessRunner,
    },
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info};
use ic_types::{
    Height, PlatformVersion, RegistryVersion, ReplicaVersion, SubnetId,
    consensus::{CatchUpPackage, HasHeight},
};
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

/// Dynamic arguments of the replica.
pub(crate) struct ReplicaArgs<'a> {
    pub platform_version: PlatformVersion,
    pub subnet_id: SubnetId,
    /// The latest CUP, which a newly started replica picks up.
    pub cup: &'a CatchUpPackage,
}

pub(crate) struct ReplicaProcess {
    ic_binary_dir: PathBuf,
    platform_version: PlatformVersion,
    cup_path: PathBuf,
    replica_config_file: PathBuf,
    subnet_id: SubnetId,
    /// Height of the CUP the replica was started with.
    cup_height: Height,
}

impl Process for ReplicaProcess {
    const NAME: &'static str = "replica";
    type Version = ReplicaVersion;
    type Config = ReplicaProcessConfig;
    type Args<'a> = ReplicaArgs<'a>;

    fn build(config: &Self::Config, args: Self::Args<'_>) -> OrchestratorResult<Self> {
        Ok(Self {
            ic_binary_dir: config.ic_binary_dir.clone(),
            platform_version: args.platform_version,
            cup_path: config.cup_path.clone(),
            replica_config_file: config.replica_config_file.clone(),
            subnet_id: args.subnet_id,
            cup_height: args.cup.height(),
        })
    }

    /// The replica must be restarted:
    /// - if the subnet ID changed, which happens on destination nodes of a subnet split, because
    ///   the subnet ID is passed as a CLI argument and kept constant throughout the lifetime of the
    ///   replica;
    /// - if the latest CUP is an unsigned (i.e. recovery) CUP higher than the CUP the replica was
    ///   started with, because consensus would reject the unsigned artifact.
    fn restart_decision(&self, args: &Self::Args<'_>) -> RestartDecision {
        let Self::Args {
            platform_version: _,
            subnet_id: new_subnet_id,
            cup: new_cup,
        } = args;

        let mut reasons = vec![];

        if *new_subnet_id != self.subnet_id {
            reasons.push(format!(
                "Subnet ID changed from {} to {}, evidence of a destination node of a subnet split",
                self.subnet_id, new_subnet_id
            ));
        }
        if !new_cup.is_signed() && new_cup.height() > self.cup_height {
            reasons.push(format!(
                "Found higher unsigned CUP (height {} > {}), evidence of a subnet recovery",
                new_cup.height(),
                self.cup_height
            ));
        }

        if reasons.is_empty() {
            RestartDecision::KeepRunning
        } else {
            RestartDecision::Restart {
                reason: reasons.join("; "),
            }
        }
    }

    fn get_version(&self) -> &Self::Version {
        &self.platform_version.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--guestos-version"),
            self.platform_version.guestos_version.to_string().into(),
            OsString::from("--replica-version"),
            self.platform_version.replica_version.to_string().into(),
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

impl IcBoundaryProcess {
    // Used in tests to assert which domain ic-boundary was started with.
    #[cfg(test)]
    pub(crate) fn domain_name(&self) -> &str {
        &self.domain_name
    }
}

impl Process for IcBoundaryProcess {
    const NAME: &'static str = "ic-boundary";
    type Version = ReplicaVersion;
    type Config = IcBoundaryProcessConfig;
    type Args<'a> = (ReplicaVersion, String);

    fn build(
        config: &Self::Config,
        (replica_version, domain_name): Self::Args<'_>,
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

    /// ic-boundary must be restarted if the node's domain name changed.
    fn restart_decision(&self, args: &Self::Args<'_>) -> RestartDecision {
        let (_new_replica_version, new_domain_name) = args;

        if *new_domain_name != self.domain_name {
            RestartDecision::Restart {
                reason: format!(
                    "Domain name changed from {} to {}",
                    self.domain_name, new_domain_name
                ),
            }
        } else {
            RestartDecision::KeepRunning
        }
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
    engine_config: EngineConfig,
}

impl Process for IcGatewayProcess {
    const NAME: &'static str = "ic-gateway";
    type Version = ReplicaVersion;
    type Config = IcGatewayProcessConfig;
    type Args<'a> = (ReplicaVersion, EngineConfig);

    fn build(
        config: &Self::Config,
        (replica_version, engine_config): Self::Args<'_>,
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

        // The shipped file only carries the general config. the engine specific
        // config is applied here as an override
        env.extend(engine_config.env_overlay(&config.acme_cache_dir)?);

        Ok(Self {
            ic_binary_dir: config.ic_binary_dir.clone(),
            replica_version,
            env,
            engine_config,
        })
    }

    fn restart_decision(&self, args: &Self::Args<'_>) -> RestartDecision {
        let (_new_replica_version, new_engine_config) = args;

        if *new_engine_config != self.engine_config {
            RestartDecision::Restart {
                reason: format!(
                    "Engine config changed from {:?} to {:?}",
                    self.engine_config, new_engine_config
                ),
            }
        } else {
            RestartDecision::KeepRunning
        }
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
// is running (restarting it if required by the process' `restart_decision`) and
// to stop it, converting errors to [`OrchestratorError`], logging them, and
// updating metrics.
// ---------------------------------------------------------------------------

pub(crate) struct ProcessManager<P: Process> {
    process_runner: Box<dyn ProcessRunner<P>>,
    process_config: P::Config,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl<P: Process> ProcessManager<P> {
    /// Used in tests to inject a mock ProcessRunner.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        process_runner: Box<dyn ProcessRunner<P>>,
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

    /// Ensures that a process is running with the given arguments: starts one if none is
    /// running, or restarts the running one if its [`Process::restart_decision`] requires it.
    pub(crate) fn ensure_running(&mut self, args: P::Args<'_>) -> OrchestratorResult<()> {
        if let Some(process) = self.process_runner.get_process() {
            match process.restart_decision(&args) {
                RestartDecision::KeepRunning => return Ok(()), // Nothing to do.
                RestartDecision::Restart { reason } => {
                    info!(self.logger, "Restarting {} process: {}", P::NAME, reason);
                    self.stop()?;

                    // Fall through to start a new process with the new arguments.
                }
            }
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

    /// Returns a read-only view of the managed process
    pub(crate) fn observer(&self) -> Arc<dyn ProcessObserver> {
        self.process_runner.observer()
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
    ic_gateway_manager: ProcessManager<IcGatewayProcess>,
    /// Engine configuration published by [`crate::cloud_engine`].
    engine_config: Arc<RwLock<Option<EngineConfig>>>,
    registry: Arc<RegistryHelper>,
}

impl MultipleProcessesManager {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        replica_manager: ProcessManager<ReplicaProcess>,
        ic_gateway_manager: ProcessManager<IcGatewayProcess>,
        engine_config: Arc<RwLock<Option<EngineConfig>>>,
        registry: Arc<RegistryHelper>,
    ) -> Self {
        Self {
            replica_manager,
            ic_gateway_manager,
            engine_config,
            registry,
        }
    }

    pub(crate) fn new(
        replica_process_config: ReplicaProcessConfig,
        ic_gateway_process_config: IcGatewayProcessConfig,
        engine_config: Arc<RwLock<Option<EngineConfig>>>,
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
            engine_config,
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
        self.ic_gateway_manager.process_runner.is_running()
    }

    /// Returns read-only views of all managed processes.
    pub(crate) fn observers(&self) -> Vec<Arc<dyn ProcessObserver>> {
        vec![
            self.replica_manager.observer(),
            self.ic_gateway_manager.observer(),
        ]
    }

    /// Start all processes appropriate for this node.
    /// If a process fails to start, continue starting the others and return the first error.
    ///
    /// Always starts the replica.  For cloud-engine subnet nodes it also
    /// starts ic-gateway.
    pub(crate) fn start_all(
        &mut self,
        platform_version: PlatformVersion,
        subnet_id: SubnetId,
        cup: &CatchUpPackage,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        let mut result = Ok(());
        result = result.and(self.replica_manager.ensure_running(ReplicaArgs {
            platform_version: platform_version.clone(),
            subnet_id,
            cup,
        }));

        // Cloud-engine nodes run ic-gateway as a sidecar.
        let maybe_engine_config = self.engine_config.read().unwrap().clone();
        if self
            .registry
            .is_cloud_engine_subnet(subnet_id, registry_version)?
            // If the engine config is `None` (either because it's not yet initialized, or because
            // it was withdrawn), we stop `ic-gateway`.
            // Do not inline reading the lock as it would hold it until the end of the `if` block
            && let Some(engine_config) = maybe_engine_config
        {
            result = result.and(
                self.ic_gateway_manager
                    .ensure_running((platform_version.replica_version, engine_config)),
            );
        } else {
            result = result.and(self.ic_gateway_manager.stop());
        }

        result
    }

    /// Stop every managed process in reverse order of startup, waiting for each to exit.
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
    use crate::process_manager::fake::{FakeProcessRunner, FakeRunnerLog};
    use assert_matches::assert_matches;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_subnet_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_consensus::{fake::Fake, make_genesis};
    use ic_test_utilities_types::ids::{NODE_1, SUBNET_1, SUBNET_2};
    use ic_types::{
        consensus::dkg::DkgSummary,
        crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    };
    use std::{path::Path, sync::Mutex};
    use tempfile::tempdir;

    fn make_cup(height: u64, signed: bool) -> CatchUpPackage {
        let mut summary = DkgSummary::fake();
        summary.height = Height::from(height);
        let mut cup = make_genesis(summary);
        if signed {
            cup.signature.signature = CombinedThresholdSigOf::new(CombinedThresholdSig(vec![1]));
        }
        cup
    }

    fn platform_version() -> PlatformVersion {
        PlatformVersion {
            guestos_version: ReplicaVersion::try_from("guestos_version").unwrap(),
            replica_version: ReplicaVersion::try_from("replica_version").unwrap(),
        }
    }

    fn replica_manager_for_test() -> (
        ProcessManager<ReplicaProcess>,
        Arc<Mutex<FakeRunnerLog<ReplicaProcess>>>,
    ) {
        let runner = FakeProcessRunner::new();
        let log = runner.log();
        let config = ReplicaProcessConfig {
            ic_binary_dir: PathBuf::from("/ic_binary"),
            cup_path: PathBuf::from("/cup"),
            replica_config_file: PathBuf::from("/ic.json5"),
        };
        let manager = ProcessManager::new_for_test(
            Box::new(runner),
            config,
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        );
        (manager, log)
    }

    #[test]
    fn replica_restarted_only_when_needed() {
        let (mut manager, log) = replica_manager_for_test();
        let mut ensure = |subnet_id, cup: &CatchUpPackage| {
            manager
                .ensure_running(ReplicaArgs {
                    platform_version: platform_version(),
                    subnet_id,
                    cup,
                })
                .unwrap();
            let log = log.lock().unwrap();
            (log.starts, log.stops)
        };

        // Not running yet: started.
        assert_eq!(ensure(SUBNET_1, &make_cup(10, true)), (1, 0));
        // Higher signed CUP: regular progress, keep running.
        assert_eq!(ensure(SUBNET_1, &make_cup(20, true)), (1, 0));
        // Higher unsigned CUP than the one it was started with: subnet recovery, restarted.
        assert_eq!(ensure(SUBNET_1, &make_cup(30, false)), (2, 1));
        // Same unsigned CUP as the one it was started with: keep running.
        assert_eq!(ensure(SUBNET_1, &make_cup(30, false)), (2, 1));
        // Different subnet ID: subnet split, restarted.
        assert_eq!(ensure(SUBNET_2, &make_cup(40, true)), (3, 2));
        assert_eq!(ensure(SUBNET_2, &make_cup(40, true)), (3, 2));
    }

    #[test]
    fn replica_started_again_after_crash() {
        let (mut manager, log) = replica_manager_for_test();
        let cup = make_cup(10, true);
        let args = || ReplicaArgs {
            platform_version: platform_version(),
            subnet_id: SUBNET_1,
            cup: &cup,
        };

        manager.ensure_running(args()).unwrap();
        // Simulate the replica exiting on its own.
        log.lock().unwrap().process = None;
        manager.ensure_running(args()).unwrap();

        let log = log.lock().unwrap();
        assert_eq!((log.starts, log.stops), (2, 0));
    }

    fn ic_gateway_process_config(dir: &Path) -> IcGatewayProcessConfig {
        let env_file = dir.join("ic-gateway.env");
        std::fs::write(&env_file, b"LISTEN_PLAIN=[::]:80").unwrap();
        IcGatewayProcessConfig {
            ic_binary_dir: dir.to_path_buf(),
            ic_gateway_env_file: env_file,
            acme_cache_dir: dir.join("acme"),
        }
    }

    fn ic_gateway_manager_for_test(
        dir: &Path,
    ) -> (
        ProcessManager<IcGatewayProcess>,
        Arc<Mutex<FakeRunnerLog<IcGatewayProcess>>>,
    ) {
        let runner = FakeProcessRunner::new();
        let log = runner.log();
        let manager = ProcessManager::new_for_test(
            Box::new(runner),
            ic_gateway_process_config(dir),
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            no_op_logger(),
        );
        (manager, log)
    }

    #[test]
    fn ic_gateway_restarted_only_when_needed() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());
        let mut ensure = |base_domain| {
            manager
                .ensure_running((
                    platform_version().replica_version,
                    EngineConfig::for_test(base_domain),
                ))
                .unwrap();
            let log = log.lock().unwrap();
            (log.starts, log.stops)
        };

        // Not running yet: started.
        assert_eq!(ensure("one.example.com"), (1, 0));
        // Unchanged config: keep running.
        assert_eq!(ensure("one.example.com"), (1, 0));
        // Changed config: restarted.
        assert_eq!(ensure("two.example.com"), (2, 1));
        assert_eq!(ensure("two.example.com"), (2, 1));

        let log = log.lock().unwrap();
        let process = log.process.as_ref().expect("ic-gateway should be running");
        assert_eq!(
            process.engine_config,
            EngineConfig::for_test("two.example.com")
        );
    }

    #[test]
    fn ic_gateway_restart_retried_after_a_failed_stop() {
        let dir = tempdir().unwrap();
        let (mut manager, log) = ic_gateway_manager_for_test(dir.path());
        let mut ensure = |base_domain| {
            manager.ensure_running((
                platform_version().replica_version,
                EngineConfig::for_test(base_domain),
            ))
        };
        let running_config = |log: &FakeRunnerLog<IcGatewayProcess>| {
            log.process
                .as_ref()
                .expect("ic-gateway should be running")
                .engine_config
                .clone()
        };

        ensure("one.example.com").unwrap();

        // The config changes, but the old process does not exit.
        log.lock().unwrap().fail_stop = true;
        assert_matches!(
            ensure("two.example.com"),
            Err(OrchestratorError::IoError(msg, _)) if msg.contains("stop")
        );
        {
            // The new process must not start while the old one may still hold the port.
            let log = log.lock().unwrap();
            assert_eq!((log.starts, log.stops), (1, 0));
            assert_eq!(
                running_config(&log),
                EngineConfig::for_test("one.example.com")
            );
        }

        // The next call retries the restart, which succeeds once the old process exits.
        log.lock().unwrap().fail_stop = false;
        ensure("two.example.com").unwrap();

        let log = log.lock().unwrap();
        assert_eq!((log.starts, log.stops), (2, 1));
        assert_eq!(
            running_config(&log),
            EngineConfig::for_test("two.example.com")
        );
    }

    const ENGINE_SUBNET: SubnetId = SUBNET_1;
    const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

    /// Builds a [`MultipleProcessesManager`] for a node of a cloud engine subnet, running
    /// `ic-gateway` with the given engine config, and returns it together with a handle to the log
    /// of `ic-gateway`'s runner.
    fn cloud_engine_processes_manager_for_test(
        dir: &Path,
        engine_config: Arc<RwLock<Option<EngineConfig>>>,
    ) -> (
        MultipleProcessesManager,
        Arc<Mutex<FakeRunnerLog<IcGatewayProcess>>>,
    ) {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        data_provider
            .add(
                &make_subnet_record_key(ENGINE_SUBNET),
                REGISTRY_VERSION,
                Some(SubnetRecord {
                    subnet_type: SubnetType::CloudEngine as i32,
                    ..Default::default()
                }),
            )
            .unwrap();
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();
        let registry = Arc::new(RegistryHelper::new(NODE_1, registry_client, no_op_logger()));

        let (replica_manager, _) = replica_manager_for_test();
        let (ic_gateway_manager, log) = ic_gateway_manager_for_test(dir);
        let manager = MultipleProcessesManager::new_for_test(
            replica_manager,
            ic_gateway_manager,
            engine_config,
            registry,
        );
        (manager, log)
    }

    fn start_all(manager: &mut MultipleProcessesManager) {
        manager
            .start_all(
                platform_version(),
                ENGINE_SUBNET,
                &make_cup(10, true),
                REGISTRY_VERSION,
            )
            .unwrap();
    }

    #[test]
    fn ic_gateway_started_only_once_the_config_is_known() {
        let dir = tempdir().unwrap();
        let engine_config = Arc::new(RwLock::new(None));
        let (mut manager, log) =
            cloud_engine_processes_manager_for_test(dir.path(), engine_config.clone());

        // It terminates TLS for the engine, so it has nothing to serve without
        // the engine's configuration.
        start_all(&mut manager);
        assert!(!manager.is_ic_gateway_running());
        assert_eq!(log.lock().unwrap().starts, 0);

        *engine_config.write().unwrap() = Some(EngineConfig::for_test("engine.example.com"));
        start_all(&mut manager);

        assert!(manager.is_ic_gateway_running());
        let log = log.lock().unwrap();
        assert_eq!((log.starts, log.stops), (1, 0));
    }

    #[test]
    fn ic_gateway_stopped_when_the_config_is_withdrawn() {
        let dir = tempdir().unwrap();
        let engine_config = Arc::new(RwLock::new(None));
        let (mut manager, log) =
            cloud_engine_processes_manager_for_test(dir.path(), engine_config.clone());

        *engine_config.write().unwrap() = Some(EngineConfig::for_test("engine.example.com"));
        start_all(&mut manager);
        assert!(manager.is_ic_gateway_running());

        *engine_config.write().unwrap() = None;
        start_all(&mut manager);

        assert!(!manager.is_ic_gateway_running());
        let log = log.lock().unwrap();
        assert_eq!((log.starts, log.stops), (1, 1));
    }

    #[test]
    fn ic_gateway_credentials_never_reach_the_argument_list() {
        let dir = tempdir().unwrap();
        let config = EngineConfig::for_test("engine.example.com");
        let process = IcGatewayProcess::build(
            &ic_gateway_process_config(dir.path()),
            (platform_version().replica_version, config.clone()),
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
        assert!(
            env.get(&OsString::from("ACME_ACCOUNT_CREDS"))
                .is_some_and(|creds| creds
                    .to_string_lossy()
                    .contains(&config.acme_account.key_pkcs8)),
            "{env:?}"
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
}
