//! AI-Node manager.
//!
//! Periodically reads the local node's `AiNodeRecord` and reconciles two
//! local concerns:
//!
//! 1. Whether `ollama.service` should be running. (As before.)
//! 2. Whether a passive state-sync replica should be running, mirroring the
//!    state of the subnet referenced by `AiNodeRecord.subnet_id`.
//!
//! Lifecycle:
//!
//! * `AiNodeRecord` absent  → no ollama, no replica, state wiped.
//! * `AiNodeRecord` present, `subnet_id = None`
//!     → ollama on, no replica, state wiped.
//! * `AiNodeRecord` present, `subnet_id = Some(s)`
//!     → ollama on, replica running with `--state-sync-only --force-subnet=s`.
//! * Subnet change `Some(a) → Some(b)` → stop replica, wipe state, then start
//!   replica for `b`.
//!
//! The on-disk cleanup mirrors what the regular `Upgrade` task does when a
//! node becomes unassigned: see `crate::state_cleanup::remove_node_state`.

use crate::{
    catch_up_package_provider::CatchUpPackageProvider,
    error::{OrchestratorError, OrchestratorResult},
    process_manager::{ProcessManager, ProcessManagerImpl},
    registry_helper::RegistryHelper,
    state_cleanup::{remove_node_state, sync_and_trim_fs},
    upgrade::ReplicaProcess,
};
use ic_logger::{ReplicaLogger, debug, info, warn};
use ic_protobuf::registry::ai_node::v1::AiNodeRecord;
use ic_types::{NodeId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
use tokio::process::Command;

/// Desired AI-node state, derived solely from the local node's `AiNodeRecord`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub(crate) enum AiNodeStatus {
    /// No `AiNodeRecord` for this node — the node is not an AI node.
    #[default]
    Idle,
    /// AI flag is set but no subnet is associated → run ollama only.
    AiOnly,
    /// AI flag is set and `subnet_id = Some(s)` → run ollama AND run a
    /// state-sync-only replica for `s`.
    SyncingFor(SubnetId),
}

impl AiNodeStatus {
    fn from_record(record: Option<&AiNodeRecord>) -> Self {
        match record {
            None => AiNodeStatus::Idle,
            Some(rec) => match rec.subnet_id.as_deref() {
                None => AiNodeStatus::AiOnly,
                Some(raw) => match PrincipalId::try_from(raw) {
                    Ok(p) => AiNodeStatus::SyncingFor(SubnetId::from(p)),
                    Err(_) => AiNodeStatus::AiOnly,
                },
            },
        }
    }

    fn ollama_should_run(&self) -> bool {
        !matches!(self, AiNodeStatus::Idle)
    }

    fn syncing_subnet(&self) -> Option<SubnetId> {
        match self {
            AiNodeStatus::SyncingFor(s) => Some(*s),
            _ => None,
        }
    }
}

pub(crate) struct AiNodeManager {
    registry: Arc<RegistryHelper>,
    cup_provider: CatchUpPackageProvider,
    replica_process: Arc<Mutex<dyn ProcessManager<ReplicaProcess>>>,
    replica_version: ReplicaVersion,
    replica_config_file: PathBuf,
    orchestrator_data_directory: PathBuf,
    node_id: NodeId,
    logger: ReplicaLogger,
    ic_binary_dir: PathBuf,
    last_applied_version: Arc<RwLock<RegistryVersion>>,
    /// Last reconciled status. Shared with the dashboard so it can render
    /// the current AI-node mode.
    status: Arc<RwLock<AiNodeStatus>>,
    /// `None` until the first successful reconcile, which forces an
    /// explicit transition regardless of cached state.
    last_status: Option<AiNodeStatus>,
}

impl AiNodeManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        cup_provider: CatchUpPackageProvider,
        replica_version: ReplicaVersion,
        replica_config_file: PathBuf,
        orchestrator_data_directory: PathBuf,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        logger: ReplicaLogger,
    ) -> Self {
        // Dedicated process manager so AI-mode replicas are supervised
        // independently from the regular `Upgrade`-managed replica (which
        // should never run on an AI node anyway).
        let replica_process: Arc<Mutex<dyn ProcessManager<ReplicaProcess>>> =
            Arc::new(Mutex::new(ProcessManagerImpl::new(logger.clone())));
        Self {
            registry,
            cup_provider,
            replica_process,
            replica_version,
            replica_config_file,
            orchestrator_data_directory,
            node_id,
            logger,
            ic_binary_dir,
            last_applied_version: Default::default(),
            status: Arc::new(RwLock::new(AiNodeStatus::Idle)),
            last_status: None,
        }
    }

    /// Returns a handle the dashboard can read to render the current
    /// AI-node status (Idle, AiOnly, or SyncingFor(subnet_id)).
    pub(crate) fn get_status_handle(&self) -> Arc<RwLock<AiNodeStatus>> {
        Arc::clone(&self.status)
    }

    #[allow(dead_code)]
    pub(crate) fn get_last_applied_version(&self) -> Arc<RwLock<RegistryVersion>> {
        Arc::clone(&self.last_applied_version)
    }

    /// One reconciliation tick. Reads the latest `AiNodeRecord`, computes the
    /// desired state, and applies any transitions.
    pub(crate) async fn check_and_update(&mut self) {
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "AiNodeManager: checking AiNodeRecord at registry version {}", registry_version
        );

        let record = match self
            .registry
            .get_ai_node_record(self.node_id, registry_version)
        {
            Ok(rec) => rec,
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

        let desired = AiNodeStatus::from_record(record.as_ref());
        // Publish desired status to the shared handle so the dashboard can
        // render it.
        *self.status.write().unwrap() = desired;

        let prev = self.last_status;
        if prev == Some(desired) {
            *self.last_applied_version.write().unwrap() = registry_version;
            return;
        }

        info!(
            self.logger,
            "AiNodeManager: status transition {:?} -> {:?}", prev, desired
        );

        if let Err(e) = self.apply_transition(prev, desired).await {
            warn!(self.logger, "AiNodeManager: transition failed: {}", e);
            // Don't update last_status: we'll retry next tick.
            return;
        }

        self.last_status = Some(desired);
        *self.last_applied_version.write().unwrap() = registry_version;
    }

    async fn apply_transition(
        &mut self,
        prev: Option<AiNodeStatus>,
        desired: AiNodeStatus,
    ) -> OrchestratorResult<()> {
        // 1. Stop replica + wipe state if transitioning away from a syncing
        //    subnet (or to a different one).
        let prev_subnet = prev.and_then(|s| s.syncing_subnet());
        let new_subnet = desired.syncing_subnet();
        let need_stop_and_wipe = match (prev_subnet, new_subnet) {
            (Some(_), None) => true,
            (Some(a), Some(b)) if a != b => true,
            _ => false,
        };
        if need_stop_and_wipe {
            self.stop_replica()?;
            self.wipe_state().await;
        }

        // 2. Reconcile ollama. Only act on actual changes (or first tick).
        let prev_ollama = prev.map(|s| s.ollama_should_run());
        let new_ollama = desired.ollama_should_run();
        if prev_ollama != Some(new_ollama) {
            let action = if new_ollama { "start" } else { "stop" };
            self.run_manage_ollama(action).await?;
            info!(
                self.logger,
                "AiNodeManager: ollama.service {}ed (status={:?})", action, desired
            );
        }

        // 3. Start replica if we now want one.
        if let Some(subnet_id) = new_subnet {
            self.ensure_state_sync_replica_running(subnet_id).await?;
        }

        Ok(())
    }

    fn stop_replica(&self) -> OrchestratorResult<()> {
        self.replica_process.lock().unwrap().stop().map_err(|e| {
            OrchestratorError::IoError(
                "AiNodeManager: failed to stop state-sync replica".to_string(),
                e,
            )
        })
    }

    async fn wipe_state(&self) {
        info!(
            self.logger,
            "AiNodeManager: wiping subnet state, consensus pool, and CUP"
        );
        if let Err(e) = remove_node_state(
            self.replica_config_file.clone(),
            self.cup_provider.get_cup_path(),
            self.orchestrator_data_directory.clone(),
        ) {
            warn!(
                self.logger,
                "AiNodeManager: remove_node_state failed: {}", e
            );
        }
        if let Err(e) = sync_and_trim_fs(&self.logger).await {
            warn!(self.logger, "AiNodeManager: sync_and_trim_fs failed: {}", e);
        }
    }

    /// Ensures a state-sync-only replica is running for the given subnet.
    /// Fetches a fresh CUP for that subnet and (re)starts the replica process.
    async fn ensure_state_sync_replica_running(
        &mut self,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<()> {
        // Fetch the latest CUP from peers / registry and persist it; the
        // replica reads the file via its `--catch-up-package` arg.
        let local_cup_proto = self.cup_provider.get_local_cup_proto();
        let _cup = self
            .cup_provider
            .get_latest_cup(local_cup_proto, subnet_id)
            .await
            .map_err(|e| {
                OrchestratorError::UpgradeError(format!(
                    "AiNodeManager: failed to fetch CUP for subnet {subnet_id}: {e:?}"
                ))
            })?;

        if self.replica_process.lock().unwrap().is_running() {
            return Ok(());
        }

        let cup_path = self.cup_provider.get_cup_path();
        let replica_binary = self.ic_binary_dir.join("replica");
        let cmd: Vec<OsString> = vec![
            format!("--replica-version={}", self.replica_version.as_ref()).into(),
            format!(
                "--config-file={}",
                self.replica_config_file.as_path().display()
            )
            .into(),
            format!("--catch-up-package={}", cup_path.as_path().display()).into(),
            format!("--force-subnet={}", subnet_id).into(),
            "--state-sync-only".into(),
        ];

        info!(
            self.logger,
            "AiNodeManager: starting state-sync-only replica for subnet {} with cup {}",
            subnet_id,
            cup_path.display()
        );

        self.replica_process
            .lock()
            .unwrap()
            .start(ReplicaProcess::new(
                self.replica_version.clone(),
                replica_binary,
                cmd,
            ))
            .map_err(|e| {
                OrchestratorError::IoError(
                    "AiNodeManager: failed to start state-sync replica".into(),
                    e,
                )
            })
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
