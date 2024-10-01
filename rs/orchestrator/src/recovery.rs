use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ic_artifact_pool::certification_pool::CertificationPoolImpl;
use ic_config::{Config, ConfigSource};
use ic_logger::{info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{NodeId, SubnetId};
use tokio::process::Command;

use crate::{
    catch_up_package_provider::CatchUpPackageProvider,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    process_manager::ProcessManager,
    registry_helper::RegistryHelper,
    upgrade::ReplicaProcess,
};

pub(crate) struct Recovery {
    node_id: NodeId,
    replica_config_file: PathBuf,
    orchestrator_data_directory: PathBuf,
    pub metrics: Arc<OrchestratorMetrics>,
    registry: Arc<RegistryHelper>,
    replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
    cup_provider: Arc<CatchUpPackageProvider>,
    logger: ReplicaLogger,
}

impl Recovery {
    pub(crate) fn new(
        node_id: NodeId,
        replica_config_file: PathBuf,
        orchestrator_data_directory: PathBuf,
        metrics: Arc<OrchestratorMetrics>,
        registry: Arc<RegistryHelper>,
        replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
        cup_provider: Arc<CatchUpPackageProvider>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            replica_config_file,
            orchestrator_data_directory,
            metrics,
            registry,
            replica_process,
            cup_provider,
            logger,
        }
    }

    /// Stop the current replica process.
    pub(crate) fn stop_replica(&self) -> OrchestratorResult<()> {
        self.replica_process.lock().unwrap().stop().map_err(|e| {
            OrchestratorError::IoError(
                "Error when attempting to stop replica during upgrade".into(),
                e,
            )
        })
    }

    pub(crate) async fn check_for_recovery(
        &self,
        subnet_id: Option<SubnetId>,
    ) -> OrchestratorResult<()> {
        let Some(subnet_id) = subnet_id else {
            return Ok(());
        };

        if !self.registry.should_create_checkpoint(subnet_id) {
            return Ok(());
        }

        info!(
            self.logger,
            "Should create checkpoint at latest certified height",
        );

        if let Err(e) = self.stop_replica() {
            warn!(self.logger, "Failed to stop replica with error {:?}", e);
        }

        let config_str = "/run/ic-node/config/ic.json5";
        let replay = "/opt/ic/bin/ic-replay";

        let tmpdir = tempfile::Builder::new()
            .prefix("ic_config")
            .tempdir()
            .map_err(|err| {
                OrchestratorError::IoError("Couldn't create a temporary directory".into(), err)
            })?;

        let config = Config::load_with_tmpdir(
            ConfigSource::File(self.replica_config_file.clone()),
            tmpdir.path().to_path_buf(),
        );

        let pool = CertificationPoolImpl::new(
            self.node_id,
            config.artifact_pool.into(),
            self.logger.clone(),
            MetricsRegistry::new(),
        );

        let Ok((height, _cert_hash)) = pool
            .persistent_pool
            .certification_shares()
            .get_highest()
            .map(|share| (share.height, share.signed.content.hash))
            .or_else(|_| {
                pool.persistent_pool
                    .certifications()
                    .get_highest()
                    .map(|cert| (cert.height, cert.signed.content.hash))
            })
        else {
            // TODO: Write the latest CUP height and hash to the data file instead
            warn!(self.logger, "No highest certification found");
            return Ok(());
        };

        info!(
            self.logger,
            "Found highest certification at height {height}",
        );

        let checkpoint_exists = self
            .cup_provider
            .get_checkpoint_heights()?
            .any(|h| h == height.get());

        if checkpoint_exists {
            info!(self.logger, "Checkpoint at height {height} already exists");
            return Ok(());
        }

        let mut cp = Command::new("cp");
        cp.arg("-R")
            .arg("/var/lib/ic/data/ic_state/checkpoints")
            .arg("/var/lib/ic/backup/checkpoints");
        let _output = self.execute_command(cp).await?;

        let mut replay = Command::new(replay);
        replay
            .arg(config_str)
            .arg("--subnet-id")
            .arg(subnet_id.to_string())
            .arg("--replay-until-height")
            .arg(height.to_string());
        let output = self.execute_command(replay).await?;

        let state_hash = self.extract_state_hash(output)?;

        let content = format!("State hash: {}, Height: {}", state_hash, height);

        info!(
            self.logger,
            "Creating recovery checkpoint data file with content: {}", content
        );
        self.create_data_file(content, self.orchestrator_data_directory.clone())?;

        Ok(())
    }

    async fn execute_command(&self, mut cmd: Command) -> OrchestratorResult<String> {
        info!(self.logger, "Executing command: {cmd:?}");
        match cmd.output().await {
            Ok(output) => {
                let stdout = String::from_utf8(output.stdout).unwrap_or_default();
                let stderr = String::from_utf8(output.stderr).unwrap_or_default();
                stdout.lines().for_each(|line| info!(self.logger, "{line}"));
                stderr.lines().for_each(|line| warn!(self.logger, "{line}"));
                Ok(stdout)
            }
            Err(err) => Err(OrchestratorError::IoError(
                format!("Failed to execute {cmd:?}"),
                err,
            )),
        }
    }

    fn extract_state_hash(&self, output: String) -> OrchestratorResult<String> {
        let prefix = "Latest state hash: ";

        for line in output.lines() {
            if let Some(hash_start) = line.strip_prefix(prefix) {
                return Ok(hash_start.trim().into());
            }
        }
        Err(OrchestratorError::RebootTimeError(
            "Did not find state hash in output".into(),
        ))
    }

    fn create_data_file(&self, content: String, dir: PathBuf) -> OrchestratorResult<()> {
        // Ensure the directory exists
        fs::create_dir_all(&dir).map_err(|err| OrchestratorError::file_write_error(&dir, err))?;

        // Create a file path by appending the filename to the directory
        let file_path = dir.join("recovery_checkpoint.txt");

        // Create and open the file for writing
        let mut file = fs::File::create(file_path.clone())
            .map_err(|err| OrchestratorError::file_write_error(&file_path, err))?;

        // Write the content to the file
        file.write_all(content.as_bytes()).map_err(|err| {
            OrchestratorError::IoError(
                format!("Failed to write content ({}) to file {:?}", content, file),
                err,
            )
        })?;

        Ok(())
    }
}
