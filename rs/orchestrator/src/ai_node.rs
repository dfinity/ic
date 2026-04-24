use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registry_helper::RegistryHelper,
};
use ic_logger::{ReplicaLogger, debug, info, warn};
use ic_types::{NodeId, RegistryVersion};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::process::Command;

/// Periodically checks the registry for an `AiNodeRecord` matching this node's
/// `NodeId` and reconciles the local `ollama.service` accordingly:
///
/// * If a record exists for this node and ollama is not running, start it.
/// * If no record exists for this node and ollama is running, stop it.
///
/// The unit is expected to be present (and disabled by default) on the image.
/// Starting/stopping is performed via `sudo /opt/ic/bin/manage-ollama.sh
/// {start,stop}` because the orchestrator runs as `ic-replica` and needs
/// root to invoke `systemctl`.
pub(crate) struct AiNodeManager {
    registry: Arc<RegistryHelper>,
    node_id: NodeId,
    logger: ReplicaLogger,
    ic_binary_dir: PathBuf,
    last_applied_version: Arc<RwLock<RegistryVersion>>,
    /// Cached desired state. `None` until the first successful reconcile.
    /// `Some(true)` means "ollama should be running" (record present).
    desired_running: Option<bool>,
}

impl AiNodeManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            node_id,
            logger,
            ic_binary_dir,
            last_applied_version: Default::default(),
            desired_running: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_last_applied_version(&self) -> Arc<RwLock<RegistryVersion>> {
        Arc::clone(&self.last_applied_version)
    }

    /// Checks the registry and (un)starts `ollama.service` if needed.
    pub(crate) async fn check_and_update(&mut self) {
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking AiNodeRecord at registry version: {}", registry_version
        );

        let should_run = match self
            .registry
            .get_ai_node_record(self.node_id, registry_version)
        {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(
                    self.logger,
                    "Failed to read AiNodeRecord for {} at registry version {}: {}",
                    self.node_id,
                    registry_version,
                    e
                );
                return;
            }
        };

        // First-time reconcile: force an explicit transition regardless of cache,
        // because on boot we do not know whether the unit was left running from a
        // previous life. After that we only act on actual changes.
        let need_transition = match self.desired_running {
            None => true,
            Some(prev) => prev != should_run,
        };

        if need_transition {
            let action = if should_run { "start" } else { "stop" };
            match self.run_manage_ollama(action).await {
                Ok(()) => {
                    info!(
                        self.logger,
                        "ollama.service {}ed (AiNodeRecord present: {})", action, should_run
                    );
                    self.desired_running = Some(should_run);
                }
                Err(e) => {
                    warn!(self.logger, "Failed to {} ollama.service: {}", action, e);
                    return;
                }
            }
        }

        *self.last_applied_version.write().unwrap() = registry_version;
    }

    async fn run_manage_ollama(&self, action: &str) -> OrchestratorResult<()> {
        let script = self.ic_binary_dir.join("manage-ollama.sh");
        let out = Command::new("sudo")
            .arg(script.as_os_str())
            .arg(action)
            .output()
            .await
            .map_err(|e| {
                OrchestratorError::IoError(format!("failed to spawn manage-ollama.sh {action}"), e)
            })?;

        if !out.status.success() {
            return Err(OrchestratorError::UpgradeError(format!(
                "manage-ollama.sh {action} failed: {:?} - stdout: {} - stderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}
