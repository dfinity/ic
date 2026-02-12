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

#[derive(Debug, Default)]
struct ReadonlyBackupKeySets {
    readonly: Vec<String>,
    backup: Vec<String>,
}

#[derive(Debug)]
struct KeySets {
    readonly_backup: OrchestratorResult<ReadonlyBackupKeySets>,
    recovery: OrchestratorResult<Vec<String>>,
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

        let key_sets = self.get_ssh_keysets(subnet_id, registry_version);

        // Update the readonly, backup & recovery keys. If it fails, log why.
        if self.update_access_keys(&key_sets) {
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

    fn update_access_keys(&self, key_sets: &KeySets) -> bool {
        let update = |account, keys_result| {
            let keys: &Vec<String> = match keys_result {
                Ok(keys) => keys,
                Err(e) => {
                    warn!(
                        every_n_seconds => 300,
                        self.logger,
                        "Cannot retrieve the {} keysets from the registry: {}", account, e
                    );
                    return false;
                }
            };
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
        let readonly_result = update(
            "readonly",
            key_sets.readonly_backup.as_ref().map(|keys| &keys.readonly),
        );
        let backup_result = update(
            "backup",
            key_sets.readonly_backup.as_ref().map(|keys| &keys.backup),
        );
        let recovery_result = update("recovery", key_sets.recovery.as_ref());
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

    fn get_ssh_keysets(&self, subnet_id: Option<SubnetId>, version: RegistryVersion) -> KeySets {
        let ssh_recovery_access = self.registry.get_ssh_recovery_access(version);
        let ssh_readonly_backup_access = match subnet_id {
            None => match self
                .registry
                .get_api_boundary_node_record(self.node_id, version)
            {
                // API boundary nodes (for now) do not have readonly or backup keys
                Ok(_) => Ok(ReadonlyBackupKeySets::default()),
                // If it is not an API boundary node, it is an unassigned node
                Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)) => match self
                    .registry
                    .get_registry_client()
                    .get_unassigned_nodes_config(version)
                    .map_err(OrchestratorError::RegistryClientError)
                {
                    // Unassigned nodes do not need backup keys
                    Ok(Some(record)) => Ok(ReadonlyBackupKeySets {
                        readonly: record.ssh_readonly_access,
                        backup: vec![],
                    }),
                    Ok(None) => Ok(ReadonlyBackupKeySets::default()),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            },
            Some(subnet_id) => {
                self.registry
                    .get_subnet_record(subnet_id, version)
                    .map(|subnet_record| ReadonlyBackupKeySets {
                        readonly: subnet_record.ssh_readonly_access,
                        backup: subnet_record.ssh_backup_access,
                    })
            }
        };
        KeySets {
            readonly_backup: ssh_readonly_backup_access,
            recovery: ssh_recovery_access,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use ic_logger::ReplicaLogger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, node::v1::NodeRecord,
        subnet::v1::SubnetRecord, unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
    };
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_node_record_key, make_subnet_record_key,
        make_unassigned_nodes_config_record_key,
    };
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::test_subnet_record;
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, NODE_3, SUBNET_0};
    use ic_types::{NodeId, RegistryVersion, SubnetId};

    use crate::{
        error::OrchestratorError,
        metrics::OrchestratorMetrics,
        registry_helper::RegistryHelper,
        ssh_access_manager::{KeySets, SshAccessManager},
    };

    const SUBNET_ID: SubnetId = SUBNET_0;
    const ASSIGNED_NODE: NodeId = NODE_1;
    const UNASSIGNED_NODE: NodeId = NODE_2;
    const API_BOUNDARY_NODE: NodeId = NODE_3;
    const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
    const REPLICA_VERSION: &str = "some_version";

    const ASSIGNED_READONLY_KEY: &str = "assigned_readonly_key";
    const UNASSIGNED_READONLY_KEY: &str = "unassigned_readonly_key";
    const BACKUP_KEY: &str = "backup_key";
    const RECOVERY_KEY: &str = "recovery_key";

    enum RegistryEntry {
        /// The Subnet/Node/API Bounday node record corresponding
        /// to this SSH key doesn't exist
        MissingRecord,
        /// No Keys of this type were deployed to registry
        NoKeys,
        /// A key of this type was deployed to registry
        KeyDeployed,
    }

    impl RegistryEntry {
        fn to_ssh_access(&self, key: &str) -> Option<Vec<String>> {
            match self {
                RegistryEntry::MissingRecord => None,
                RegistryEntry::NoKeys => Some(vec![]),
                RegistryEntry::KeyDeployed => Some(vec![key.to_string()]),
            }
        }
    }

    struct TestCase {
        assigned_readonly: RegistryEntry,
        unassigned_readonly: RegistryEntry,
        backup: RegistryEntry,
        recovery: RegistryEntry,
    }

    impl KeySets {
        fn has_assigned_readonly(&self) -> bool {
            self.readonly_backup
                .as_ref()
                .is_ok_and(|keys| keys.readonly == vec![ASSIGNED_READONLY_KEY.to_string()])
        }
        fn has_unassigned_readonly(&self) -> bool {
            self.readonly_backup
                .as_ref()
                .is_ok_and(|keys| keys.readonly == vec![UNASSIGNED_READONLY_KEY.to_string()])
        }
        fn has_empty_readonly(&self) -> bool {
            self.readonly_backup
                .as_ref()
                .is_ok_and(|keys| keys.readonly.is_empty())
        }
        fn has_recovery(&self) -> bool {
            self.recovery
                .as_ref()
                .is_ok_and(|keys| *keys == vec![RECOVERY_KEY.to_string()])
        }
        fn has_empty_recovery(&self) -> bool {
            self.recovery.as_ref().is_ok_and(|keys| keys.is_empty())
        }
        fn has_backup(&self) -> bool {
            self.readonly_backup
                .as_ref()
                .is_ok_and(|keys| keys.backup == vec![BACKUP_KEY.to_string()])
        }
        fn has_empty_backup(&self) -> bool {
            self.readonly_backup
                .as_ref()
                .is_ok_and(|keys| keys.backup.is_empty())
        }
    }

    fn setup_registry(test: &TestCase) -> Arc<FakeRegistryClient> {
        let ssh_assigned_readonly_access =
            test.assigned_readonly.to_ssh_access(ASSIGNED_READONLY_KEY);
        let ssh_unassigned_readonly_access = test
            .unassigned_readonly
            .to_ssh_access(UNASSIGNED_READONLY_KEY);
        let ssh_backup_access = test.backup.to_ssh_access(BACKUP_KEY);
        let ssh_recovery_access = test.recovery.to_ssh_access(RECOVERY_KEY);

        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        if ssh_assigned_readonly_access.is_some() || ssh_backup_access.is_some() {
            let subnet_record = SubnetRecord {
                ssh_readonly_access: ssh_assigned_readonly_access.clone().unwrap_or_default(),
                ssh_backup_access: ssh_backup_access.unwrap_or_default(),
                membership: vec![ASSIGNED_NODE.get().to_vec()],
                ..test_subnet_record()
            };
            registry_data
                .add(
                    &make_subnet_record_key(SUBNET_ID),
                    REGISTRY_VERSION,
                    Some(subnet_record),
                )
                .expect("Failed to add subnet record.");
        }

        if let Some(ssh_readonly_access) = ssh_unassigned_readonly_access {
            registry_data
                .add(
                    &make_unassigned_nodes_config_record_key(),
                    REGISTRY_VERSION,
                    Some(UnassignedNodesConfigRecord {
                        ssh_readonly_access,
                        replica_version: REPLICA_VERSION.into(),
                    }),
                )
                .expect("Failed to add unassigned nodes record.");
        }

        if let Some(ssh_node_state_write_access) = ssh_recovery_access {
            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                registry_data
                    .add(
                        &make_node_record_key(node_id),
                        REGISTRY_VERSION,
                        Some(NodeRecord {
                            ssh_node_state_write_access: ssh_node_state_write_access.clone(),
                            ..Default::default()
                        }),
                    )
                    .expect("Failed to add node record.");
            }
        }

        registry_data
            .add(
                &make_api_boundary_node_record_key(API_BOUNDARY_NODE),
                REGISTRY_VERSION,
                Some(ApiBoundaryNodeRecord {
                    version: REPLICA_VERSION.into(),
                }),
            )
            .expect("Failed to add boundary node record.");

        registry_client.reload();
        registry_client
    }

    fn setup_ssh_access_manager(
        node_id: NodeId,
        test: &TestCase,
        logger: &ReplicaLogger,
    ) -> SshAccessManager {
        let registry_client = setup_registry(test);
        let registry = RegistryHelper::new(node_id, registry_client, logger.clone());
        let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());
        SshAccessManager::new(
            Arc::new(registry),
            Arc::new(metrics),
            node_id,
            logger.clone(),
        )
    }

    #[test]
    fn test_get_all_keys_assigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::KeyDeployed,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::KeyDeployed,
            };

            // Regardless of what the registry says, if the orchestrator says we are assigned to a subnet
            // then we will apply the subnet's keys
            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);
                assert!(keys.has_assigned_readonly());
                assert!(keys.has_backup());
                assert!(keys.has_recovery());
            }
        })
    }

    #[test]
    fn test_get_all_keys_unassigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::KeyDeployed,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::KeyDeployed,
            };

            // Regardless of what the registry says, if the orchestrator says we are unassigned
            // then we will not apply the subnet's keys
            for node_id in [ASSIGNED_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);
                assert!(keys.has_unassigned_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_recovery());
            }

            let manager = setup_ssh_access_manager(API_BOUNDARY_NODE, &test, &log);
            let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);
            assert!(keys.has_empty_readonly());
            assert!(keys.has_empty_backup());
            assert!(keys.has_recovery());
        })
    }

    #[test]
    fn test_no_keys_assigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_empty_recovery());
            }
        })
    }

    #[test]
    fn test_no_keys_unassigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_empty_recovery());
            }
        })
    }

    #[test]
    fn test_readonly_assigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::KeyDeployed,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert!(keys.has_assigned_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_empty_recovery());
            }
        })
    }

    #[test]
    fn test_readonly_unassigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);

                assert!(keys.has_unassigned_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_empty_recovery());
            }

            // API boundary nodes do not use the unassigned readonly keys
            let manager = setup_ssh_access_manager(API_BOUNDARY_NODE, &test, &log);
            let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);

            assert!(keys.has_empty_readonly());
            assert!(keys.has_empty_backup());
            assert!(keys.has_empty_recovery());
        })
    }

    #[test]
    fn test_backup_assigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_backup());
                assert!(keys.has_empty_recovery());
            }
        })
    }

    #[test]
    fn test_backup_unassigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::NoKeys,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_empty_recovery());
            }
        })
    }

    #[test]
    fn test_recovery_assigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::KeyDeployed,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_recovery());
            }
        })
    }

    #[test]
    fn test_recovery_unassigned() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::NoKeys,
                unassigned_readonly: RegistryEntry::NoKeys,
                backup: RegistryEntry::NoKeys,
                recovery: RegistryEntry::KeyDeployed,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);

                assert!(keys.has_empty_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_recovery());
            }
        })
    }

    #[test]
    fn test_assigned_node_fails_without_subnet_record() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::MissingRecord,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::MissingRecord,
                recovery: RegistryEntry::KeyDeployed,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert_matches!(
                    keys.readonly_backup,
                    Err(OrchestratorError::SubnetMissingError(_, _))
                );
                assert!(keys.has_recovery());
            }
        })
    }

    #[test]
    fn test_unassigned_node_succeeds_without_subnet_record() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::MissingRecord,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::MissingRecord,
                recovery: RegistryEntry::KeyDeployed,
            };

            for node_id in [ASSIGNED_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);
                assert!(keys.has_unassigned_readonly());
                assert!(keys.has_empty_backup());
                assert!(keys.has_recovery());
            }

            let manager = setup_ssh_access_manager(API_BOUNDARY_NODE, &test, &log);
            let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION);
            assert!(keys.has_empty_readonly());
            assert!(keys.has_empty_backup());
            assert!(keys.has_recovery());
        })
    }

    #[test]
    fn test_recovery_fails_without_node_record() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::KeyDeployed,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::MissingRecord,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                let keys = manager.get_ssh_keysets(Some(SUBNET_ID), REGISTRY_VERSION);

                assert_matches!(
                    keys.recovery,
                    Err(OrchestratorError::NodeRecordMissingError(_, _))
                );
                assert!(keys.has_assigned_readonly());
                assert!(keys.has_backup());
            }
        })
    }

    #[test]
    fn test_get_keysets_fails_for_unknown_registry_version() {
        with_test_replica_logger(|log| {
            let test = TestCase {
                assigned_readonly: RegistryEntry::KeyDeployed,
                unassigned_readonly: RegistryEntry::KeyDeployed,
                backup: RegistryEntry::KeyDeployed,
                recovery: RegistryEntry::KeyDeployed,
            };

            for node_id in [ASSIGNED_NODE, API_BOUNDARY_NODE, UNASSIGNED_NODE] {
                let manager = setup_ssh_access_manager(node_id, &test, &log);
                // Use unknown registry version
                let keys = manager.get_ssh_keysets(None, REGISTRY_VERSION.increment());

                assert_matches!(
                    keys.readonly_backup,
                    Err(OrchestratorError::RegistryClientError(_))
                );
                assert_matches!(
                    keys.recovery,
                    Err(OrchestratorError::RegistryClientError(_))
                );
            }
        })
    }
}
