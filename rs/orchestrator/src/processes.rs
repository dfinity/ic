use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessRunner, RestartDecision, SingleProcessRunner},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_types::{
    Height, PlatformVersion, RegistryVersion, ReplicaVersion, SubnetId,
    consensus::{CatchUpPackage, HasHeight},
};
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
        let mut reasons = vec![];

        if args.subnet_id != self.subnet_id {
            reasons.push(format!(
                "Subnet ID changed from {} to {}, evidence of a destination node of a subnet split",
                self.subnet_id, args.subnet_id
            ));
        }
        if !args.cup.is_signed() && args.cup.height() > self.cup_height {
            reasons.push(format!(
                "Found higher unsigned CUP (height {} > {}), evidence of a subnet recovery",
                args.cup.height(),
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
    fn restart_decision(&self, (_, domain_name): &Self::Args<'_>) -> RestartDecision {
        if *domain_name != self.domain_name {
            RestartDecision::Restart {
                reason: format!(
                    "Domain name changed from {} to {}",
                    self.domain_name, domain_name
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
    type Args<'a> = ReplicaVersion;

    fn build(config: &Self::Config, replica_version: Self::Args<'_>) -> OrchestratorResult<Self> {
        let env = match crate::env_file::read_file(&config.ic_gateway_env_file) {
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

    fn restart_decision(&self, _args: &Self::Args<'_>) -> RestartDecision {
        RestartDecision::KeepRunning
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
        match self.process_runner.restart_decision(&args) {
            // Not running
            None => {}
            Some(RestartDecision::KeepRunning) => return Ok(()),
            Some(RestartDecision::Restart { reason }) => {
                info!(self.logger, "Restarting {} process: {}", P::NAME, reason);
                self.stop()?;
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
                    result = result.and(self.ic_gateway_manager.stop());
                }
                Some(SubnetType::CloudEngine) => {
                    result = result.and(
                        self.ic_gateway_manager
                            .ensure_running(platform_version.replica_version),
                    );
                }
            }
        }

        result
    }

    /// Stop every managed process in reverse order of startup, waiting for each to exit.
    /// If a process fails to stop, continue stopping the others and return the first error.
    pub(crate) fn stop_all(&mut self) -> OrchestratorResult<()> {
        let mut result = Ok(());
        if self.ic_gateway_launch_enabled {
            result = result.and(self.ic_gateway_manager.stop());
        }
        result = result.and(self.replica_manager.stop());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_manager::fake::{FakeProcessRunner, FakeRunnerLog};
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::{fake::Fake, make_genesis};
    use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2};
    use ic_types::{
        consensus::dkg::DkgSummary,
        crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    };
    use std::sync::Mutex;

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
}
