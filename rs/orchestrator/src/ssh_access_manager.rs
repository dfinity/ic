use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    registry_helper::RegistryHelper,
};
use ic_logger::{ReplicaLogger, debug, warn};
use ic_registry_client_helpers::unassigned_nodes::UnassignedNodeRegistry;
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::{Arc, RwLock},
};

#[derive(Default)]
pub(crate) struct SshAccessParameters {
    pub registry_version: RegistryVersion,
    pub subnet_id: Option<SubnetId>,
}

struct KeySets {
    readonly: Vec<String>,
    backup: Vec<String>,
    recovery: Vec<String>,
}

/// Provides function to continuously check the Registry to determine if there
/// has been a change in the readonly, backup or recovery public key sets. If so,
/// updates the access to the node accordingly.
pub(crate) struct SshAccessManager {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    node_id: NodeId,
    logger: ReplicaLogger,
    last_applied_parameters: Arc<RwLock<SshAccessParameters>>,
}

impl SshAccessManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        node_id: NodeId,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            metrics,
            node_id,
            logger,
            last_applied_parameters: Default::default(),
        }
    }

    /// Checks for changes in the keysets, and updates the node accordingly.
    pub(crate) fn check_for_keyset_changes(&mut self, subnet_id: Option<SubnetId>) {
        let registry_version = self.registry.get_latest_version();
        let last_applied_parameters = self.last_applied_parameters.read().unwrap();
        if last_applied_parameters.registry_version == registry_version
            && last_applied_parameters.subnet_id == subnet_id
        {
            return;
        }
        drop(last_applied_parameters);
        debug!(
            self.logger,
            "Checking for the access keys in the registry version {} for subnet_id {:?}",
            registry_version,
            subnet_id
        );

        let key_sets = match self.get_keysets(subnet_id, registry_version) {
            Err(error) => {
                warn!(
                    every_n_seconds => 300,
                    self.logger,
                    "Cannot retrieve the readonly, backup or recovery keysets from the registry {}", error
                );
                return;
            }
            Ok(keys) => keys,
        };

        // Update the readonly, backup & recovery keys. If it fails, log why.
        if self.update_access_keys(key_sets) {
            *self.last_applied_parameters.write().unwrap() = SshAccessParameters {
                registry_version,
                subnet_id,
            };
            self.metrics
                .ssh_access_registry_version
                .set(registry_version.get() as i64);
        }
    }

    pub(crate) fn get_last_applied_parameters(&self) -> Arc<RwLock<SshAccessParameters>> {
        Arc::clone(&self.last_applied_parameters)
    }

    fn update_access_keys(&self, key_sets: KeySets) -> bool {
        let update = |account, keys| {
            self.update_access_to_one_account(account, keys)
                .map_err(|e| {
                    warn!(
                        every_n_seconds => 300,
                        self.logger,
                        "Could not update the {} keys due to a script failure: {}", account, e
                    );
                })
                .is_ok()
        };
        let readonly_result = update("readonly", &key_sets.readonly);
        let backup_result = update("backup", &key_sets.backup);
        let recovery_result = update("recovery", &key_sets.recovery);
        readonly_result && backup_result && recovery_result
    }

    // If `keys` is empty, pre-existing keys will be deleted
    fn update_access_to_one_account(&self, account: &str, keys: &[String]) -> Result<(), String> {
        let mut cmd = Command::new("/opt/ic/bin/provision-ssh-keys.sh")
            .arg(account)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn child process: {e}"))?;

        let mut stdin = cmd
            .stdin
            .take()
            .ok_or_else(|| "Failed to open stdin".to_string())?;
        let key_list = keys.join("\n");
        stdin
            .write_all(key_list.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {e}"))?;
        drop(stdin);

        match cmd.wait_with_output() {
            Err(e) => Err(e.to_string()),
            _ => Ok(()),
        }
    }

    fn get_keysets(
        &self,
        subnet_id: Option<SubnetId>,
        version: RegistryVersion,
    ) -> OrchestratorResult<KeySets> {
        let ssh_recovery_access = self.registry.get_ssh_recovery_access(version)?;
        let (ssh_readonly_access, ssh_backup_access) = match subnet_id {
            None => match self
                .registry
                .get_api_boundary_node_record(self.node_id, version)
            {
                // API boundary nodes (for now) do not have readonly or backup keys
                Ok(_) => Ok((vec![], vec![])),
                // If it is not an API boundary node, it is an unassigned node
                Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)) => match self
                    .registry
                    .registry_client
                    .get_unassigned_nodes_config(version)
                    .map_err(OrchestratorError::RegistryClientError)?
                {
                    // Unassigned nodes do not need backup keys
                    Some(record) => Ok((record.ssh_readonly_access, vec![])),
                    None => Ok((vec![], vec![])),
                },
                Err(err) => Err(err),
            },
            Some(subnet_id) => {
                self.registry
                    .get_subnet_record(subnet_id, version)
                    .map(|subnet_record| {
                        (
                            subnet_record.ssh_readonly_access,
                            subnet_record.ssh_backup_access,
                        )
                    })
            }
        }?;
        Ok(KeySets {
            readonly: ssh_readonly_access,
            backup: ssh_backup_access,
            recovery: ssh_recovery_access,
        })
    }
}
