use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::{Process, ProcessRunner, SingleProcessRunner, start_orchestrator_process},
    registry_helper::RegistryHelper,
};
use ic_config::crypto::CryptoConfig;
use ic_logger::{ReplicaLogger, warn};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_types::{RegistryVersion, ReplicaVersion, SubnetId};
use nix::unistd::Pid;
use std::{
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::Arc,
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

impl ReplicaProcess {
    pub(crate) fn new(
        config: ReplicaProcessConfig,
        replica_version: ReplicaVersion,
        subnet_id: SubnetId,
    ) -> Self {
        Self {
            ic_binary_dir: config.ic_binary_dir,
            replica_version,
            cup_path: config.cup_path,
            replica_config_file: config.replica_config_file,
            subnet_id,
        }
    }
}

impl Process for ReplicaProcess {
    const NAME: &'static str = "replica";
    type Version = ReplicaVersion;

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

pub(crate) struct ReplicaManager {
    pub process_runner: Box<dyn ProcessRunner<ReplicaProcess> + Sync>,
    process_config: ReplicaProcessConfig,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl ReplicaManager {
    pub(crate) fn new(
        process_config: ReplicaProcessConfig,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let process_runner = Box::new(SingleProcessRunner::new(logger.clone()));
        Self {
            process_runner,
            process_config,
            metrics,
            logger,
        }
    }

    fn ensure_replica_running(
        &mut self,
        replica_version: &ReplicaVersion,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<()> {
        start_orchestrator_process(
            &mut *self.process_runner,
            ReplicaProcess::new(
                self.process_config.clone(),
                replica_version.clone(),
                subnet_id,
            ),
            &self.metrics,
            &self.logger,
        )
    }

    fn stop_replica(&mut self) -> OrchestratorResult<()> {
        self.process_runner.stop().map_err(|e| {
            OrchestratorError::IoError("Error when attempting to stop replica".to_string(), e)
        })
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
    pub(crate) fn new(
        process_config: IcBoundaryProcessConfig,
        replica_version: ReplicaVersion,
        domain_name: String,
    ) -> OrchestratorResult<Self> {
        let env = match env_file_reader::read_file(&process_config.ic_boundary_env_file) {
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
        let crypto_config = serde_json::to_string(&process_config.crypto_config)
            .map_err(OrchestratorError::SerializeCryptoConfigError)?;

        Ok(Self {
            ic_binary_dir: process_config.ic_binary_dir,
            replica_version,
            domain_name,
            crypto_config,
            env,
        })
    }
}

impl Process for IcBoundaryProcess {
    const NAME: &'static str = "ic-boundary";
    type Version = ReplicaVersion;

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

pub(crate) struct IcBoundaryManager {
    pub process_runner: Box<dyn ProcessRunner<IcBoundaryProcess> + Sync>,
    process_config: IcBoundaryProcessConfig,
    registry: Arc<RegistryHelper>,
    pub current_domain_name: Option<String>,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl IcBoundaryManager {
    pub(crate) fn new(
        process_config: IcBoundaryProcessConfig,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let process_runner = Box::new(SingleProcessRunner::new(logger.clone()));
        Self {
            process_runner,
            process_config,
            registry,
            current_domain_name: None,
            metrics,
            logger,
        }
    }

    pub(crate) fn ensure_ic_boundary_running_and_restarted_on_domain_change(
        &mut self,
        replica_version: &ReplicaVersion,
        registry_version: RegistryVersion,
    ) {
        match self.registry.get_node_domain_name(registry_version) {
            Ok(Some(domain_name)) => {
                // stop ic-boundary when the domain name changes and start it again.
                if Some(&domain_name) != self.current_domain_name.as_ref()
                    && let Err(err) = self.stop_ic_boundary()
                {
                    warn!(self.logger, "Failed to stop ic-boundary: {}", err);
                }

                // make sure the ic-boundary is running
                if let Err(err) = self.ensure_ic_boundary_running(replica_version, &domain_name) {
                    warn!(self.logger, "Failed to start ic-boundary: {}", err);
                }

                self.current_domain_name = Some(domain_name);
            }
            // ic-boundary should not start when the node doesn't have a domain name
            Ok(None) => {
                warn!(
                    self.logger,
                    "There is no domain associated with the node, while this is a requirement for the API boundary node. Shutting ic-boundary down."
                );
                if let Err(err) = self.stop_ic_boundary() {
                    warn!(self.logger, "Failed to stop Boundary Node: {}", err);
                }
                self.current_domain_name = None;
            }
            // Failing to read the registry
            Err(err) => warn!(self.logger, "Failed to fetch domain name: {}", err),
        }
    }

    fn ensure_ic_boundary_running(
        &mut self,
        replica_version: &ReplicaVersion,
        domain_name: &str,
    ) -> OrchestratorResult<()> {
        start_orchestrator_process(
            &mut *self.process_runner,
            IcBoundaryProcess::new(
                self.process_config.clone(),
                replica_version.clone(),
                domain_name.to_string(),
            )?,
            &self.metrics,
            &self.logger,
        )
    }

    pub(crate) fn stop_ic_boundary(&mut self) -> OrchestratorResult<()> {
        self.process_runner.stop().map_err(|e| {
            OrchestratorError::IoError("Error when attempting to stop ic-boundary".to_string(), e)
        })
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

impl IcGatewayProcess {
    pub(crate) fn new(
        process_config: IcGatewayProcessConfig,
        replica_version: ReplicaVersion,
    ) -> OrchestratorResult<Self> {
        let env = match env_file_reader::read_file(&process_config.ic_gateway_env_file) {
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
            ic_binary_dir: process_config.ic_binary_dir,
            replica_version,
            env,
        })
    }
}

impl Process for IcGatewayProcess {
    const NAME: &'static str = "ic-gateway";
    type Version = ReplicaVersion;

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

pub(crate) struct IcGatewayManager {
    pub process_runner: Box<dyn ProcessRunner<IcGatewayProcess> + Sync>,
    process_config: IcGatewayProcessConfig,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
}

impl IcGatewayManager {
    pub(crate) fn new(
        process_config: IcGatewayProcessConfig,
        metrics: Arc<OrchestratorMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let process_runner = Box::new(SingleProcessRunner::new(logger.clone()));
        Self {
            process_runner,
            process_config,
            metrics,
            logger,
        }
    }

    fn ensure_ic_gateway_running(
        &mut self,
        replica_version: &ReplicaVersion,
    ) -> OrchestratorResult<()> {
        start_orchestrator_process(
            &mut *self.process_runner,
            IcGatewayProcess::new(self.process_config.clone(), replica_version.clone())?,
            &self.metrics,
            &self.logger,
        )
    }

    fn stop_ic_gateway(&mut self) -> OrchestratorResult<()> {
        self.process_runner.stop().map_err(|e| {
            OrchestratorError::IoError("Error when attempting to stop ic-gateway".to_string(), e)
        })
    }
}

// ---------------------------------------------------------------------------
// MultipleProcessManager
//
// This struct manages all processes that the orchestrator is responsible for,
// providing a single entry point for starting and stopping them according to
// the node's configuration in the registry.
// ---------------------------------------------------------------------------

pub(crate) struct MultipleProcessesManager {
    replica_manager: ReplicaManager,
    ic_gateway_manager: IcGatewayManager,
    registry: Arc<RegistryHelper>,
}

impl MultipleProcessesManager {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        replica_manager: ReplicaManager,
        ic_gateway_manager: IcGatewayManager,
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
            ReplicaManager::new(replica_process_config, metrics.clone(), logger.clone());
        let ic_gateway_manager = IcGatewayManager::new(ic_gateway_process_config, metrics, logger);

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
        replica_version: &ReplicaVersion,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        self.replica_manager
            .ensure_replica_running(replica_version, subnet_id)?;

        // Cloud-engine nodes run ic-gateway as a sidecar.
        match self.registry.get_subnet_type(subnet_id, registry_version)? {
            None
            | Some(SubnetType::Unspecified)
            | Some(SubnetType::Application)
            | Some(SubnetType::System)
            | Some(SubnetType::VerifiedApplication) => {
                self.ic_gateway_manager.stop_ic_gateway()?;
            }
            Some(SubnetType::CloudEngine) => {
                self.ic_gateway_manager
                    .ensure_ic_gateway_running(replica_version)?;
            }
        }

        Ok(())
    }

    /// Stop the replica process.
    pub(crate) fn stop_replica(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop_replica()
    }

    /// Stop every managed process.
    pub(crate) fn stop_all(&mut self) -> OrchestratorResult<()> {
        self.replica_manager.stop_replica()?;
        self.ic_gateway_manager.stop_ic_gateway()?;

        Ok(())
    }
}
