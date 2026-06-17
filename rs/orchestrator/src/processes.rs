use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessRunner, SingleProcessRunner},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, info, warn};
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
    logger: ReplicaLogger,
}

impl IcBoundaryManager {
    pub(crate) fn new(
        config: <IcBoundaryProcess as Process>::Config,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let inner = ProcessManager::new(config, metrics, logger.clone());
        Self {
            inner,
            registry,
            current_domain_name: None,
            logger,
        }
    }

    pub(crate) fn ensure_ic_boundary_running_and_restarted_on_domain_change(
        &mut self,
        replica_version: ReplicaVersion,
        registry_version: RegistryVersion,
    ) {
        match self.registry.get_node_domain_name(registry_version) {
            Ok(Some(domain_name)) => {
                // stop ic-boundary when the domain name changes and start it again.
                if Some(&domain_name) != self.current_domain_name.as_ref()
                    && let Err(err) = self.inner.stop()
                {
                    warn!(
                        self.logger,
                        "Failed to stop {}: {}",
                        IcBoundaryProcess::NAME,
                        err
                    );
                }

                // make sure ic-boundary is running
                if let Err(err) = self
                    .inner
                    .ensure_running((replica_version, domain_name.clone()))
                {
                    warn!(
                        self.logger,
                        "Failed to start {}: {}",
                        IcBoundaryProcess::NAME,
                        err
                    );
                }

                self.current_domain_name = Some(domain_name);
            }
            // ic-boundary should not start when the node doesn't have a domain name
            Ok(None) => {
                warn!(
                    self.logger,
                    "There is no domain associated with the node, while this is a requirement for the API boundary node. Shutting {} down.",
                    IcBoundaryProcess::NAME
                );
                if let Err(err) = self.inner.stop() {
                    warn!(
                        self.logger,
                        "Failed to stop {}: {}",
                        IcBoundaryProcess::NAME,
                        err
                    );
                }
                self.current_domain_name = None;
            }
            // Failing to read the registry
            Err(err) => warn!(self.logger, "Failed to fetch domain name: {}", err),
        }
    }

    pub(crate) fn stop(&mut self) -> OrchestratorResult<()> {
        self.inner.stop()
    }
}

// ---------------------------------------------------------------------------
// MultipleProcessManager
//
// This struct manages all processes that the upgrade loop is responsible for,
// providing a single entry point for starting and stopping them according to
// the node's configuration in the registry.
// ---------------------------------------------------------------------------

pub(crate) struct MultipleProcessesManager {
    replica_manager: ProcessManager<ReplicaProcess>,
    ic_gateway_manager: ProcessManager<IcGatewayProcess>,
    registry: Arc<RegistryHelper>,
}

impl MultipleProcessesManager {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        replica_manager: ProcessManager<ReplicaProcess>,
        ic_gateway_manager: ProcessManager<IcGatewayProcess>,
        registry: Arc<RegistryHelper>,
    ) -> Self {
        Self {
            replica_manager,
            ic_gateway_manager,
            registry,
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

        // Cloud-engine nodes run ic-gateway as a sidecar.
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

        Ok(())
    }

    /// Stop the replica process.
    pub(crate) fn stop_replica(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop()
    }

    /// Stop every managed process.
    pub(crate) fn stop_all(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop()?;
        self.ic_gateway_manager.stop()?;

        Ok(())
    }
}
