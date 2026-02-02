//! Node Operator Migration
//!
//! This module provides functionality for node providers to migrate node operator
//! records from one principal to another within the same data center.
use std::{
    fmt::Display,
    time::{Duration, SystemTime},
};

use candid::{CandidType, Principal};
use ic_nervous_system_time_helpers::now_system_time;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::{delete, pb::v1::RegistryMutation, upsert};
use ic_types::PrincipalId;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    mutations::node_management::common::get_node_operator_nodes_with_id, registry::Registry,
};

/// Minimum age a node operator must have before it can be migrated.
/// This prevents spam by requiring operators to exist for at least this duration
/// before they can be deleted through migration.
const MIGRATION_CAPACITY_INTERVAL_HOURS: u64 = 12;

/// The duration form of [`MIGRATION_CAPACITY_INTERVAL_HOURS`].
const MIGRATION_CAPACITY_INTERVAL: Duration =
    Duration::from_secs(MIGRATION_CAPACITY_INTERVAL_HOURS * 60 * 60);

impl Registry {
    /// Migrates a node operator record and node records to a new node operator principal.
    /// If the migration is successful, the old node operator record is removed from the
    /// registry.
    ///
    /// This is the public entry point called by the canister. It retrieves the caller
    /// and current time, then delegates to the inner implementation.
    ///
    /// # Panics
    ///
    /// Panics if any business rule validation fails. See [`MigrateError`] for possible
    /// failure reasons.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let payload = MigrateNodeOperatorPayload {
    ///     old_node_operator_id: Some(old_principal),
    ///     new_node_operator_id: Some(new_principal),
    /// };
    /// registry.do_migrate_node_operator_directly(payload);
    /// ```
    pub fn do_migrate_node_operator_directly(&mut self, payload: MigrateNodeOperatorPayload) {
        self.migrate_node_operator_inner(payload, dfn_core::api::caller(), now_system_time())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Internal implementation of node operator migration with injectable dependencies.
    fn migrate_node_operator_inner(
        &mut self,
        payload: MigrateNodeOperatorPayload,
        caller: PrincipalId,
        now: SystemTime,
    ) -> Result<(), MigrateError> {
        // Check if the payload is valid by itself.
        payload.validate()?;
        let (old_node_operator_id, new_node_operator_id) = (
            payload.old_node_operator_id.unwrap(),
            payload.new_node_operator_id.unwrap(),
        );

        let mut total_mutations = self.get_operator_mutations_if_business_rules_are_valid(
            old_node_operator_id,
            new_node_operator_id,
            caller,
            now,
        )?;

        total_mutations.extend(self.get_node_mutations(old_node_operator_id, new_node_operator_id));

        self.maybe_apply_mutation_internal(total_mutations);

        Ok(())
    }

    /// Validates all business rules and returns the mutations for node operator records.
    ///
    /// The validation checks the following business rules:
    /// 1. The old node operator record must exist.
    /// 2. The caller must be the owner (Node Provider) of the old node operator record.
    /// 3. The old node operator record must have been created at least
    ///    [`MIGRATION_CAPACITY_INTERVAL`] ago.
    /// 4. The new node operator record (if it exists) must be owned by the same Node Provider
    ///    as the old one.
    /// 5. Both node operator records must belong to the same Data Center.
    fn get_operator_mutations_if_business_rules_are_valid(
        &self,
        old_node_operator_id: PrincipalId,
        new_node_operator_id: PrincipalId,
        caller: PrincipalId,
        now: SystemTime,
    ) -> Result<Vec<RegistryMutation>, MigrateError> {
        // Old node operator record must exist
        let (old_node_operator_record, timestamp_created_nanos) = self
            .get(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                self.latest_version(),
            )
            .ok_or(MigrateError::MissingNodeOperator {
                principal: old_node_operator_id,
            })
            .map(|registry_value| {
                (
                    NodeOperatorRecord::decode(registry_value.value.as_slice()).unwrap(),
                    registry_value.timestamp_nanoseconds,
                )
            })?;

        // The caller must be the owner of both of the node operator
        // records.
        if caller.to_vec() != old_node_operator_record.node_provider_principal_id {
            return Err(MigrateError::NotAuthorized {
                caller,
                expected: PrincipalId(Principal::from_slice(
                    &old_node_operator_record.node_provider_principal_id,
                )),
            });
        }

        // Check that the old operator was created at least MIGRATION_CAPACITY_INTERVAL ago
        // to prevent rapid empty operator migrations (spam prevention).
        let created_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_nanos(timestamp_created_nanos))
            .expect("SystemTime before UNIX EPOCH");
        let age = now
            .duration_since(created_at)
            .expect("Record created in the future which is impossible");

        if age < MIGRATION_CAPACITY_INTERVAL {
            return Err(MigrateError::OldOperatorRateLimit {
                principal: old_node_operator_id,
            });
        }

        // New node operator record can exist, but doesn't have to.
        //
        // If it doesn't exist it should be created on the fly.
        let mut new_node_operator_record = self
            .get(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                self.latest_version(),
            )
            .map(|registry_value| {
                NodeOperatorRecord::decode(registry_value.value.as_slice()).unwrap()
            })
            .unwrap_or(NodeOperatorRecord {
                node_operator_principal_id: new_node_operator_id.to_vec(),
                node_provider_principal_id: old_node_operator_record
                    .node_provider_principal_id
                    .clone(),
                dc_id: old_node_operator_record.dc_id.clone(),
                // Other fields will be handled later
                ..Default::default()
            });

        // Both records must be owned by the same node provider.
        if old_node_operator_record.node_provider_principal_id
            != new_node_operator_record.node_provider_principal_id
        {
            return Err(MigrateError::NodeProviderMismatch {
                old: PrincipalId(Principal::from_slice(
                    &old_node_operator_record.node_provider_principal_id,
                )),
                new: PrincipalId(Principal::from_slice(
                    &new_node_operator_record.node_provider_principal_id,
                )),
            });
        }

        // Both records must be within the same data center.
        //
        // This is needed to not allow nodes to be transferred to different
        // locations with this feature.
        //
        // Transfering still must be done with redeployments.
        if old_node_operator_record.dc_id != new_node_operator_record.dc_id {
            return Err(MigrateError::DataCenterMismatch {
                old: old_node_operator_record.dc_id.clone(),
                new: new_node_operator_record.dc_id.clone(),
            });
        }

        // Business rules hold. We can update the records.
        Self::update_new_node_operator_record(
            &old_node_operator_record,
            &mut new_node_operator_record,
        );

        Ok(vec![
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                new_node_operator_record.encode_to_vec(),
            ),
            delete(make_node_operator_record_key(old_node_operator_id).as_bytes()),
        ])
    }

    /// Merges data from the old node operator record into the new node operator record.
    ///
    /// The update is performed as follows:
    /// 1. `node_allowance` is added from the old record to the new record.
    /// 2. `ipv6` field is copied from the old record (legacy field).
    /// 3. `rewardable_nodes` map counts are merged: values from the old record are added to the new one.
    /// 4. `max_rewardable_nodes` map counts are merged: values from the old record are added to the new one.
    fn update_new_node_operator_record(
        old_node_operator_record: &NodeOperatorRecord,
        new_node_operator_record: &mut NodeOperatorRecord,
    ) {
        new_node_operator_record.node_allowance += old_node_operator_record.node_allowance;

        // IPv6 is a legacy field and it isn't used anymore.
        new_node_operator_record.ipv6 = old_node_operator_record.ipv6.clone();

        for (node_reward_type, value) in &old_node_operator_record.rewardable_nodes {
            *new_node_operator_record
                .rewardable_nodes
                .entry(node_reward_type.to_string())
                .or_insert(0) += value;
        }

        for (node_reward_type, value) in &old_node_operator_record.max_rewardable_nodes {
            *new_node_operator_record
                .max_rewardable_nodes
                .entry(node_reward_type.to_string())
                .or_insert(0) += value;
        }
    }

    /// Generates mutations to transfer all nodes from old node operator to new node
    /// operator.
    ///
    /// Scans the registry for all nodes owned by `old_node_operator_id` and creates
    /// mutations that update their `node_operator_id` field to point to
    /// `new_node_operator_id`.
    fn get_node_mutations(
        &self,
        old_node_operator_id: PrincipalId,
        new_node_operator_id: PrincipalId,
    ) -> Vec<RegistryMutation> {
        get_node_operator_nodes_with_id(self, old_node_operator_id)
            .into_iter()
            .map(|(key, mut record)| {
                record.node_operator_id = new_node_operator_id.to_vec();
                upsert(make_node_record_key(key).as_bytes(), record.encode_to_vec())
            })
            .collect()
    }
}

/// Payload for the node operator migration operation.
///
/// Both fields are required; the migration will fail with [`MigrateError::MissingInput`]
/// if either is `None`.
#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct MigrateNodeOperatorPayload {
    /// Represents the principal of the target node operator to which
    /// the migration is being executed.
    ///
    /// If this node operator exists, it will just be updated to match
    /// the data present in the old node operator record.
    ///
    /// If this node operator doesn't exist, it will be created.
    #[prost(message, optional, tag = "1")]
    pub new_node_operator_id: Option<PrincipalId>,

    /// Represents the principal of the current node operator from which
    /// the migration is being executed.
    ///
    /// This node operator record will be removed if the migration is
    /// successful.
    #[prost(message, optional, tag = "2")]
    pub old_node_operator_id: Option<PrincipalId>,
}

/// Errors that can occur during node operator migration.
///
/// Each variant includes relevant context to help diagnose the issue.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrateError {
    /// One or both of the operator IDs in the payload are missing.
    MissingInput,

    /// The old and new operator IDs are identical.
    SamePrincipals,

    /// The specified old node operator does not exist in the registry.
    MissingNodeOperator { principal: PrincipalId },

    /// The old and new operators belong to different node providers.
    NodeProviderMismatch { old: PrincipalId, new: PrincipalId },

    /// The old and new operators are in different data centers.
    DataCenterMismatch { old: String, new: String },

    /// The caller is not the node provider that owns the operators.
    NotAuthorized {
        caller: PrincipalId,
        expected: PrincipalId,
    },

    /// The old operator was created too recently and cannot be migrated yet.
    /// Operators must exist for at least [`MIGRATION_CAPACITY_INTERVAL_HOURS`] hours.
    OldOperatorRateLimit { principal: PrincipalId },
}

impl Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MigrateError::MissingInput => "The provided payload has missing data".to_string(),
                MigrateError::SamePrincipals =>
                    "`new_node_operator_id` and `old_node_operator_id` must differ".to_string(),

                MigrateError::MissingNodeOperator { principal } =>
                    format!("Expected node operator {principal} to exist, but it doesn't"),
                MigrateError::NodeProviderMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are controlled by the same node provider. Instead got old node provider principal: {old}, new node provider principal: {new}"
                ),
                MigrateError::DataCenterMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are within the same data center. Instead got old data center: {old}, new data center: {new}"
                ),
                MigrateError::NotAuthorized { caller, expected } => format!(
                    "Caller doesn't seem to be the node provider owning the operator records that are being changed. Expected {expected}, got {caller}"
                ),
                MigrateError::OldOperatorRateLimit { principal } => format!(
                    "Old node operator {principal} was created too recently (within last {MIGRATION_CAPACITY_INTERVAL_HOURS} hours) and thus cannot be removed yet"
                ),
            }
        )
    }
}

impl MigrateNodeOperatorPayload {
    fn validate(&self) -> Result<(), MigrateError> {
        let (old_node_operator_id, new_node_operator_id) =
            match (&self.old_node_operator_id, &self.new_node_operator_id) {
                (Some(old_node_operator_id), Some(new_node_operator_id)) => {
                    (old_node_operator_id, new_node_operator_id)
                }
                _ => return Err(MigrateError::MissingInput),
            };

        if old_node_operator_id == new_node_operator_id {
            return Err(MigrateError::SamePrincipals);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        time::{Duration, SystemTime},
    };

    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_nervous_system_time_helpers::now_system_time;
    use ic_protobuf::registry::{
        node::v1::{ConnectionEndpoint, NodeRecord, NodeRewardType},
        node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_keys::{NODE_RECORD_KEY_PREFIX, make_node_operator_record_key};
    use ic_registry_transport::{
        pb::v1::{HighCapacityRegistryDelta, RegistryMutation},
        upsert,
    };
    use ic_types::{NodeId, PrincipalId};
    use itertools::Itertools;
    use prost::Message;

    use crate::{
        common::test_helpers::invariant_compliant_registry,
        mutations::{
            do_migrate_node_operator_directly::{MigrateError, MigrateNodeOperatorPayload},
            node_management::common::make_add_node_registry_mutations,
        },
        registry::Registry,
    };

    fn invalid_payloads_with_expected_errors() -> Vec<(MigrateNodeOperatorPayload, MigrateError)> {
        vec![
            (
                MigrateNodeOperatorPayload {
                    new_node_operator_id: None,
                    old_node_operator_id: None,
                },
                MigrateError::MissingInput,
            ),
            (
                MigrateNodeOperatorPayload {
                    new_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
                    old_node_operator_id: None,
                },
                MigrateError::MissingInput,
            ),
            (
                MigrateNodeOperatorPayload {
                    new_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
                    old_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
                },
                MigrateError::SamePrincipals,
            ),
        ]
    }

    /// Returns a timestamp 13 hours in the future.
    ///
    /// Since test data is seeded at the current time, the rate limit check would
    /// fail for newly created operators. This helper bypasses that by simulating
    /// a call 13 hours later (past the 12-hour limit).
    ///
    /// # Limitations
    ///
    /// This only works because we inject `now` into `migrate_node_operator_inner`.
    /// The actual registry mutations still use real system time, so full rate limit
    /// testing requires PocketIC where time can be controlled.
    fn now_plus_13_hours() -> SystemTime {
        let now = now_system_time();

        now + Duration::from_secs(13 * 60 * 60)
    }

    #[test]
    fn invalid_payloads() {
        let mut registry = Registry::new();

        for (payload, expected_err) in invalid_payloads_with_expected_errors() {
            let output = registry.migrate_node_operator_inner(
                payload.clone(),
                PrincipalId::new_user_test_id(1),
                now_plus_13_hours(),
            );

            let expected = Err(expected_err);
            assert_eq!(output, expected, "{payload:?}");
        }
    }

    #[test]
    fn missing_old_node_operator() {
        let mut registry = Registry::new();

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
            new_node_operator_id: Some(PrincipalId::new_user_test_id(2)),
        };

        let original_registry = registry.clone();
        let resp = registry.migrate_node_operator_inner(
            payload.clone(),
            PrincipalId::new_user_test_id(3),
            now_plus_13_hours(),
        );

        assert_eq!(registry, original_registry);

        let expected_err = Err(MigrateError::MissingNodeOperator {
            principal: payload.old_node_operator_id.unwrap(),
        });
        assert_eq!(resp, expected_err);
    }

    #[test]
    fn node_provider_mismatch() {
        let mut registry = Registry::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let old_node_provider_id = PrincipalId::new_user_test_id(3);
        let new_node_provider_id = PrincipalId::new_user_test_id(4);

        let dc_id = "dc".to_string();

        let mutations = vec![
            upsert(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: old_node_operator_id.to_vec(),
                    node_provider_principal_id: old_node_provider_id.to_vec(),
                    dc_id: dc_id.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: new_node_operator_id.to_vec(),
                    node_provider_principal_id: new_node_provider_id.to_vec(),
                    dc_id: dc_id.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ];

        registry.apply_mutations_for_test(mutations);

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(old_node_operator_id),
            new_node_operator_id: Some(new_node_operator_id),
        };

        let original_registry = registry.clone();
        let resp = registry.migrate_node_operator_inner(
            payload.clone(),
            old_node_provider_id,
            now_plus_13_hours(),
        );
        assert_eq!(original_registry, registry);

        let expected_err = Err(MigrateError::NodeProviderMismatch {
            old: old_node_provider_id,
            new: new_node_provider_id,
        });
        assert_eq!(resp, expected_err)
    }

    #[test]
    fn data_center_mismatch() {
        let mut registry = Registry::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(3);

        let dc1 = "dc1".to_string();
        let dc2 = "dc2".to_string();

        let mutations = vec![
            upsert(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: old_node_operator_id.to_vec(),
                    node_provider_principal_id: node_provider_id.to_vec(),
                    dc_id: dc1.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: new_node_operator_id.to_vec(),
                    node_provider_principal_id: node_provider_id.to_vec(),
                    dc_id: dc2.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ];

        registry.apply_mutations_for_test(mutations);

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(old_node_operator_id),
            new_node_operator_id: Some(new_node_operator_id),
        };

        let original_registry = registry.clone();
        let resp =
            registry.migrate_node_operator_inner(payload, node_provider_id, now_plus_13_hours());
        assert_eq!(original_registry, registry);

        let expected_err = Err(MigrateError::DataCenterMismatch { old: dc1, new: dc2 });
        assert_eq!(resp, expected_err)
    }

    #[test]
    fn caller_not_owning_node_operator_records() {
        let mut registry = Registry::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(3);

        let dc = "dc1".to_string();

        let mutations = vec![
            upsert(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: old_node_operator_id.to_vec(),
                    node_provider_principal_id: node_provider_id.to_vec(),
                    dc_id: dc.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: new_node_operator_id.to_vec(),
                    node_provider_principal_id: node_provider_id.to_vec(),
                    dc_id: dc.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ];

        registry.apply_mutations_for_test(mutations);

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(old_node_operator_id),
            new_node_operator_id: Some(new_node_operator_id),
        };

        let caller = PrincipalId::new_user_test_id(999);
        assert_ne!(caller, node_provider_id);

        let original_registry = registry.clone();
        let resp = registry.migrate_node_operator_inner(payload, caller, now_plus_13_hours());
        assert_eq!(original_registry, registry);

        let expected_err = Err(MigrateError::NotAuthorized {
            caller,
            expected: node_provider_id,
        });
        assert_eq!(resp, expected_err)
    }

    #[derive(Clone)]
    struct NodeInformation {
        node_operator: PrincipalId,
        valid_pks: ValidNodePublicKeys,
    }

    impl NodeInformation {
        fn new(node_operator: PrincipalId) -> Self {
            let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
            let keys = generate_node_keys_once(&config, None).unwrap();

            Self {
                node_operator,
                valid_pks: keys,
            }
        }

        fn node_id(&self) -> NodeId {
            self.valid_pks.node_id()
        }

        fn to_upsert_mutations(&self, index: usize) -> Vec<RegistryMutation> {
            // Some of the indices are already added to the invariant registry
            let ip_addr = format!("128.0.{}.1", 200 - index);
            make_add_node_registry_mutations(
                self.node_id(),
                NodeRecord {
                    xnet: Some(ConnectionEndpoint {
                        ip_addr: ip_addr.clone(),
                        port: 1234,
                    }),
                    http: Some(ConnectionEndpoint {
                        ip_addr,
                        port: 4321,
                    }),
                    node_operator_id: self.node_operator.to_vec(),
                    ..Default::default()
                },
                self.valid_pks.clone(),
            )
        }
    }

    /// Test fixture that provides a pre-configured registry and tracks added nodes.
    struct TestSetup {
        /// Nodes that have been added during the test, tracked for verification.
        nodes: Vec<NodeInformation>,
        /// The registry under test.
        registry: Registry,
    }

    impl TestSetup {
        fn new() -> Self {
            Self {
                registry: invariant_compliant_registry(1),
                nodes: vec![],
            }
        }

        fn add_node(&mut self, node_operator: PrincipalId) {
            let node = NodeInformation::new(node_operator);

            self.nodes.push(node.clone());

            let mutations = node.to_upsert_mutations(self.nodes.len());

            self.registry.maybe_apply_mutation_internal(mutations);
        }

        fn add_node_operator(
            &mut self,
            node_operator_id: PrincipalId,
            node_provider_id: PrincipalId,
            node_allowance: u64,
            dc: &str,
            rewardable_nodes: Vec<(String, u32)>,
            max_rewardable_nodes: Vec<(String, u32)>,
        ) {
            let node_operator_record = NodeOperatorRecord {
                node_operator_principal_id: node_operator_id.to_vec(),
                node_allowance,
                node_provider_principal_id: node_provider_id.to_vec(),
                dc_id: dc.to_string(),
                max_rewardable_nodes: max_rewardable_nodes.into_iter().collect(),
                rewardable_nodes: rewardable_nodes.into_iter().collect(),
                ..Default::default()
            };

            self.registry.maybe_apply_mutation_internal(vec![upsert(
                make_node_operator_record_key(node_operator_id).as_bytes(),
                node_operator_record.encode_to_vec(),
            )]);
        }

        fn fetch_nodes_originally_for_node_operator(
            &self,
            node_operator_id: PrincipalId,
        ) -> Vec<NodeRecord> {
            self.nodes
                .iter()
                .filter(|node_info| node_info.node_operator == node_operator_id)
                .map(|node_info| self.registry.get_node_or_panic(node_info.node_id()))
                .collect()
        }
    }

    #[test]
    fn successful_migration_when_new_operator_doesnt_exist() {
        // Step 1: Prepare the world, i.e. populate the Registry.
        let mut setup = TestSetup::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(999);

        // Operator spec variables
        let rewardable_nodes = vec![
            (NodeRewardType::Type1.to_string(), 5),
            (NodeRewardType::Type2.to_string(), 10),
        ];
        let node_allowance = 5;
        let dc = "dc";

        setup.add_node_operator(
            old_node_operator_id,
            node_provider_id,
            node_allowance,
            dc,
            rewardable_nodes.clone(),
            rewardable_nodes.clone(),
        );

        // Add 3 nodes owned by the node operator under test
        for _ in 0..3 {
            setup.add_node(old_node_operator_id);
        }

        // Add 3 nodes owned by a random operator that shouldn't be
        // changed
        let extra_node_operator = PrincipalId::new_user_test_id(333);
        for _ in 0..5 {
            setup.add_node(extra_node_operator);
        }

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(old_node_operator_id),
            new_node_operator_id: Some(new_node_operator_id),
        };

        let old_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(old_node_operator_id);

        let extra_node_records =
            setup.fetch_nodes_originally_for_node_operator(extra_node_operator);

        // Step 2: Run the code under test.
        setup
            .registry
            .migrate_node_operator_inner(payload, node_provider_id, now_plus_13_hours())
            .unwrap();

        // Setup 3: Verify results.

        // Ensure that the new operator is there
        let new_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(new_node_operator_id);

        // Ensure that the values are inherited from the old record
        assert_eq!(
            new_node_operator_record,
            NodeOperatorRecord {
                node_operator_principal_id: new_node_operator_id.to_vec(),
                ..old_node_operator_record
            }
        );

        // Ensure that the old operator isn't there
        let old_node_operator_record = setup.registry.get(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            setup.registry.latest_version(),
        );
        assert_eq!(old_node_operator_record, None);

        // Ensure that the nodes owned by the old operator show the new operator now
        let nodes = setup.fetch_nodes_originally_for_node_operator(old_node_operator_id);
        assert_eq!(nodes.len(), 3, "{nodes:?}");
        for node in nodes {
            assert_eq!(node.node_operator_id, new_node_operator_id.to_vec());
        }

        // Ensure that the extra nodes weren't touched
        let nodes = setup.fetch_nodes_originally_for_node_operator(extra_node_operator);
        assert_eq!(nodes.len(), 5, "{nodes:?}");
        for (new_node_record, extra_node_record) in nodes
            .into_iter()
            .sorted_by_key(|n| n.http.clone().unwrap().ip_addr)
            .zip(
                extra_node_records
                    .into_iter()
                    .sorted_by_key(|n| n.http.clone().unwrap().ip_addr),
            )
        {
            assert_eq!(new_node_record, extra_node_record);
        }

        // Validate number of mutations and their keys, values are checked above
        let changes = setup
            .registry
            .get_changes_since(setup.registry.latest_version() - 1, None);

        assert_eq!(changes.len(), 5);

        // Node changes
        // NOTE: Content verification was done earlier so having weak checks
        // for length and `is_present()` just ensure that mutations were there
        let node_deltas = filter_changes_for_key_prefix(NODE_RECORD_KEY_PREFIX, &changes);
        assert_eq!(node_deltas.len(), 3);
        assert!(
            node_deltas
                .iter()
                .all(|delta| delta.values.len() == 1 && delta.values[0].is_present())
        );

        // Old node operator should not be present
        let old_node_operator_deltas = filter_changes_for_key_prefix(
            make_node_operator_record_key(old_node_operator_id).as_str(),
            &changes,
        );
        assert_eq!(old_node_operator_deltas.len(), 1);
        assert!(
            old_node_operator_deltas[0].values.len() == 1
                && !old_node_operator_deltas[0].values[0].is_present()
        );

        // New node operator should be present
        let new_node_operator_deltas = filter_changes_for_key_prefix(
            make_node_operator_record_key(new_node_operator_id).as_str(),
            &changes,
        );
        assert_eq!(new_node_operator_deltas.len(), 1);
        assert!(
            new_node_operator_deltas[0].values.len() == 1
                && new_node_operator_deltas[0].values[0].is_present()
        );
    }

    fn filter_changes_for_key_prefix(
        prefix: &str,
        deltas: &[HighCapacityRegistryDelta],
    ) -> Vec<HighCapacityRegistryDelta> {
        deltas
            .iter()
            .filter(|delta| delta.key.starts_with(prefix.as_bytes()))
            .cloned()
            .collect()
    }

    #[test]
    fn successful_migration_when_new_operator_exist() {
        // Setup 1: Prepare the world, i.e. populate the Registry.
        let mut setup = TestSetup::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(999);

        // Old Operator spec variables
        let old_rewardable_nodes = vec![
            (NodeRewardType::Type1.to_string(), 5),
            (NodeRewardType::Type2.to_string(), 10),
        ];
        let node_allowance = 5;
        let dc = "dc";

        setup.add_node_operator(
            old_node_operator_id,
            node_provider_id,
            node_allowance,
            dc,
            old_rewardable_nodes.clone(),
            old_rewardable_nodes.clone(),
        );
        // Add nodes owned by the old node operator under test
        for _ in 0..3 {
            setup.add_node(old_node_operator_id);
        }

        // New operator spec variables
        let new_rewardable_nodes = vec![(NodeRewardType::Type1.to_string(), 1)];
        let new_node_allowance = 5;

        setup.add_node_operator(
            new_node_operator_id,
            node_provider_id,
            new_node_allowance,
            dc,
            new_rewardable_nodes.clone(),
            new_rewardable_nodes.clone(),
        );
        // Add nodes owned by the new node operator under test
        for _ in 0..4 {
            setup.add_node(new_node_operator_id);
        }

        // Add 4 nodes owned by a random operator that shouldn't be
        // changed
        let extra_node_operator = PrincipalId::new_user_test_id(333);
        for _ in 0..5 {
            setup.add_node(extra_node_operator);
        }

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(old_node_operator_id),
            new_node_operator_id: Some(new_node_operator_id),
        };

        let old_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(old_node_operator_id);

        let new_records = setup.fetch_nodes_originally_for_node_operator(new_node_operator_id);
        let old_node_records = setup.fetch_nodes_originally_for_node_operator(old_node_operator_id);
        let extra_records = setup.fetch_nodes_originally_for_node_operator(extra_node_operator);

        // Step 2: Run the code under test.
        setup
            .registry
            .migrate_node_operator_inner(payload, node_provider_id, now_plus_13_hours())
            .unwrap();

        // Step 3: Verify the results.

        // Ensure that the new operator is there
        let new_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(new_node_operator_id);

        // Ensure that the values are inherited from the old record
        assert_eq!(
            new_node_operator_record,
            NodeOperatorRecord {
                node_operator_principal_id: new_node_operator_id.to_vec(),
                node_allowance: node_allowance + new_node_allowance,
                // Rewardable nodes are checked later due to complex
                // migration logic.
                rewardable_nodes: new_node_operator_record.rewardable_nodes.clone(),
                max_rewardable_nodes: new_node_operator_record.max_rewardable_nodes.clone(),
                ..old_node_operator_record
            }
        );
        let rewardable_nodes: BTreeMap<_, _> = old_rewardable_nodes.into_iter().collect();
        let new_rewardable_nodes: BTreeMap<_, _> = new_rewardable_nodes.into_iter().collect();
        compare_rewardable_nodes(
            new_node_operator_record.rewardable_nodes,
            rewardable_nodes.clone(),
            new_rewardable_nodes.clone(),
        );
        compare_rewardable_nodes(
            new_node_operator_record.max_rewardable_nodes,
            rewardable_nodes.clone(),
            new_rewardable_nodes.clone(),
        );

        // Ensure that the old operator isn't there
        let old_node_operator_record = setup.registry.get(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            setup.registry.latest_version(),
        );
        assert_eq!(old_node_operator_record, None);

        // Ensure that the nodes owned by the old operator show the new operator now
        let nodes = setup.fetch_nodes_originally_for_node_operator(old_node_operator_id);
        assert_eq!(nodes.len(), 3, "{nodes:?}");
        for (new_node_record, old_node_record) in nodes
            .into_iter()
            .sorted_by_key(|n| n.http.clone().unwrap().ip_addr)
            .zip(
                old_node_records
                    .into_iter()
                    .sorted_by_key(|n| n.http.clone().unwrap().ip_addr),
            )
        {
            assert_eq!(
                new_node_record,
                NodeRecord {
                    node_operator_id: new_node_record.node_operator_id.to_vec(),
                    ..old_node_record
                }
            );
        }
        // Ensure that the nodes owned by the new operator still are owned by the
        // same node operator
        let nodes = setup.fetch_nodes_originally_for_node_operator(new_node_operator_id);
        assert_eq!(nodes.len(), 4, "{nodes:?}");
        for (new_node_record, old_node_record) in nodes
            .into_iter()
            .sorted_by_key(|n| n.xnet.clone().unwrap().ip_addr)
            .zip(
                new_records
                    .into_iter()
                    .sorted_by_key(|n| n.xnet.clone().unwrap().ip_addr),
            )
        {
            assert_eq!(new_node_record, old_node_record);
        }

        // Ensure that the extra nodes weren't touched
        let nodes = setup.fetch_nodes_originally_for_node_operator(extra_node_operator);
        assert_eq!(nodes.len(), 5, "{nodes:?}");
        for (new_node_record, old_node_record) in nodes
            .into_iter()
            .sorted_by_key(|n| n.xnet.clone().unwrap().ip_addr)
            .zip(
                extra_records
                    .into_iter()
                    .sorted_by_key(|n| n.xnet.clone().unwrap().ip_addr),
            )
        {
            assert_eq!(new_node_record, old_node_record);
        }

        // Validate number of mutations and their keys, values are checked above
        let changes = setup
            .registry
            .get_changes_since(setup.registry.latest_version() - 1, None);

        assert_eq!(changes.len(), 5);

        // Node changes
        // NOTE: Content verification was done earlier so having weak checks
        // for length and `is_present()` just ensure that mutations were there
        let node_deltas = filter_changes_for_key_prefix(NODE_RECORD_KEY_PREFIX, &changes);
        assert_eq!(node_deltas.len(), 3);
        assert!(
            node_deltas
                .iter()
                .all(|delta| delta.values.len() == 1 && delta.values[0].is_present())
        );

        // Old node operator should not be pressent
        let old_node_operator_deltas = filter_changes_for_key_prefix(
            make_node_operator_record_key(old_node_operator_id).as_str(),
            &changes,
        );
        assert_eq!(old_node_operator_deltas.len(), 1);
        assert!(
            old_node_operator_deltas[0].values.len() == 1
                && !old_node_operator_deltas[0].values[0].is_present()
        );

        // New node operator should be present
        let new_node_operator_deltas = filter_changes_for_key_prefix(
            make_node_operator_record_key(new_node_operator_id).as_str(),
            &changes,
        );
        assert_eq!(new_node_operator_deltas.len(), 1);
        assert!(
            new_node_operator_deltas[0].values.len() == 1
                && new_node_operator_deltas[0].values[0].is_present()
        );
    }

    fn compare_rewardable_nodes(
        observed: BTreeMap<String, u32>,
        old: BTreeMap<String, u32>,
        new: BTreeMap<String, u32>,
    ) {
        let mut new_mut = new;
        let mut old_mut = old;

        for (expected_key, expected_value) in observed.iter() {
            let old_value = old_mut.remove(expected_key).unwrap_or_default();
            let new_value = new_mut.remove(expected_key).unwrap_or_default();

            assert_eq!(
                *expected_value,
                old_value + new_value,
                "Expected value {expected_value} for key {expected_key} but got something else. Merging of (max_)rewardable_nodes wasn't successful."
            );
        }

        assert!(
            new_mut.is_empty(),
            "Leftover values in new (max_)rewardable_nodes which weren't carried over properly, {new_mut:?}"
        );
        assert!(
            old_mut.is_empty(),
            "Leftover values in old (max_)rewardable_nodes which weren't carried over properly, {old_mut:?}"
        );
    }

    #[test]
    fn old_node_operator_rate_limits() {
        let mut registry = invariant_compliant_registry(1);

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(999);
        registry.maybe_apply_mutation_internal(vec![upsert(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            NodeOperatorRecord {
                node_operator_principal_id: old_node_operator_id.to_vec(),
                node_provider_principal_id: node_provider_id.to_vec(),
                dc_id: "dc".to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        )]);

        let payload = MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_node_operator_id),
            old_node_operator_id: Some(old_node_operator_id),
        };

        let original_registry = registry.clone();
        let resp = registry.migrate_node_operator_inner(
            payload.clone(),
            node_provider_id,
            now_system_time(),
        );
        assert_eq!(original_registry, registry);

        let expected_err = Err(MigrateError::OldOperatorRateLimit {
            principal: old_node_operator_id,
        });
        assert_eq!(resp, expected_err);

        let resp =
            registry.migrate_node_operator_inner(payload, node_provider_id, now_plus_13_hours());

        assert_eq!(resp, Ok(()));
    }

    #[test]
    #[should_panic]
    fn expect_panic_if_created_node_operator_from_future() {
        let mut registry = invariant_compliant_registry(1);

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let node_provider_id = PrincipalId::new_user_test_id(999);
        registry.maybe_apply_mutation_internal(vec![upsert(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            NodeOperatorRecord {
                node_operator_principal_id: old_node_operator_id.to_vec(),
                node_provider_principal_id: node_provider_id.to_vec(),
                dc_id: "dc".to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        )]);

        let payload = MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_node_operator_id),
            old_node_operator_id: Some(old_node_operator_id),
        };

        let now = now_system_time();
        let past = now - Duration::from_secs(4 * 60 * 60);

        let original_registry = registry.clone();
        let resp = registry.migrate_node_operator_inner(payload.clone(), node_provider_id, past);
        assert_eq!(original_registry, registry);

        let expected_err = Err(MigrateError::OldOperatorRateLimit {
            principal: old_node_operator_id,
        });
        assert_eq!(resp, expected_err);

        let resp =
            registry.migrate_node_operator_inner(payload, node_provider_id, now_plus_13_hours());

        assert_eq!(resp, Ok(()));
    }

    #[test]
    fn migrate_whole_data_center_to_one_node_operator() {
        // Step 1: Populate the world, i.e. populate the Registry.
        let mut setup = TestSetup::new();

        let node_provider_id = PrincipalId::new_user_test_id(999);
        let dc = "dc";

        let old_node_operators: Vec<_> = (1..=3).map(PrincipalId::new_user_test_id).collect();

        let node_allowance_per_node_operator = 5;
        let rewardable_nodes_type_1_per_operator = 3;
        let rewardable_nodes_per_node_operator: Vec<_> = vec![(
            NodeRewardType::Type1.to_string(),
            rewardable_nodes_type_1_per_operator,
        )];

        for node_operator in &old_node_operators {
            setup.add_node_operator(
                *node_operator,
                node_provider_id,
                node_allowance_per_node_operator,
                dc,
                rewardable_nodes_per_node_operator.clone(),
                rewardable_nodes_per_node_operator.clone(),
            );

            for _ in 0..3 {
                setup.add_node(*node_operator);
            }
        }

        let destination_node_operator = PrincipalId::new_user_test_id(42);

        // Step 2: Run the code under test for each node operator.
        for old_node_operator in &old_node_operators {
            let payload = MigrateNodeOperatorPayload {
                old_node_operator_id: Some(*old_node_operator),
                new_node_operator_id: Some(destination_node_operator),
            };

            let resp = setup.registry.migrate_node_operator_inner(
                payload,
                node_provider_id,
                now_plus_13_hours(),
            );
            assert_eq!(resp, Ok(()));
        }

        // Step 3: Verify results.

        // Everything was migrated, now try migrating to a new one from destination_node_operator
        //
        // NOTE: this cannot be tested here since the registry doesn't expose an api
        // for changing the ingestion time of mutations. While it could be added
        // with small effort, it would be a rare use case of such feature and thus
        // this will be tested in integration tests with PocketIC where time can be controlled.
        //
        // The following logic is here to remind the reader that this shouldn't be possible.
        // ```
        // let too_soon_new_node_operator = PrincipalId::new_user_test_id(456);
        //
        // let payload = MigrateNodeOperatorPayload {
        //     old_node_operator_id: Some(destination_node_operator),
        //     new_node_operator_id: Some(too_soon_new_node_operator),
        // };
        // let resp = setup
        //     .registry
        //     .migrate_node_operator_inner(payload, caller, now_plus_13_hours());
        // let expected_err = Err(MigrateError::OldOperatorRateLimit {
        //     principal: destination_node_operator,
        // });
        // assert_eq!(resp, expected_err);
        // ```

        // Validate that old node operators have been removed
        for old_node_operator in &old_node_operators {
            let maybe_record = setup.registry.get(
                make_node_operator_record_key(*old_node_operator).as_bytes(),
                setup.registry.latest_version(),
            );

            assert_eq!(maybe_record, None, "{old_node_operator}");

            // Validate that all of the nodes have been moved to the new node operator
            for node in setup.fetch_nodes_originally_for_node_operator(*old_node_operator) {
                assert_eq!(node.node_operator_id, destination_node_operator.to_vec());
            }
        }

        // Validate correct aggregation in the new node operator
        let record = setup
            .registry
            .get_node_operator_or_panic(destination_node_operator);

        assert_eq!(record.node_provider_principal_id, node_provider_id.to_vec());
        assert_eq!(
            record.node_allowance,
            node_allowance_per_node_operator * old_node_operators.len() as u64
        );
        assert_eq!(record.dc_id, dc.to_string());
        assert_eq!(record.rewardable_nodes.len(), 1);
        let type_1_rewardable_nodes = record
            .rewardable_nodes
            .get(&NodeRewardType::Type1.to_string())
            .unwrap();
        assert_eq!(
            *type_1_rewardable_nodes,
            old_node_operators.len() as u32 * rewardable_nodes_type_1_per_operator
        );

        assert_eq!(record.max_rewardable_nodes.len(), 1);
        let type_1_max_rewardable_nodes = record
            .max_rewardable_nodes
            .get(&NodeRewardType::Type1.to_string())
            .unwrap();
        assert_eq!(
            *type_1_max_rewardable_nodes,
            old_node_operators.len() as u32 * rewardable_nodes_type_1_per_operator
        );
    }
}
