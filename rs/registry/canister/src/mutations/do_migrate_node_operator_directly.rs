use std::{
    cell::RefCell,
    fmt::Display,
    time::{Duration, SystemTime},
};

use candid::{CandidType, Principal};
use ic_nervous_system_rate_limits::{InMemoryRateLimiter, RateLimiterConfig};
use ic_nervous_system_time_helpers::now_system_time;
use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::{delete, pb::v1::RegistryMutation, upsert};
use ic_types::{NodeId, PrincipalId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    mutations::node_management::common::get_node_operator_nodes_with_id, registry::Registry,
};

const MIGRATION_CAPACITY_INTERVAL_HOURS: u64 = 12;
const MIGRATION_CAPACITY_INTERVAL: Duration =
    Duration::from_secs(MIGRATION_CAPACITY_INTERVAL_HOURS * 60 * 60);

thread_local! {
    static MIGRATION_LIMITER: RefCell<InMemoryRateLimiter<NodeId>> = RefCell::new(InMemoryRateLimiter::new_in_memory(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: MIGRATION_CAPACITY_INTERVAL,
                max_capacity: 1,
                max_reservations: 1
            })
        );
}

impl Registry {
    pub fn do_migrate_node_operator_directly(&mut self, payload: MigrateNodeOperatorPayload) {
        self.migrate_node_operator_inner(payload, dfn_core::api::caller(), now_system_time())
            .unwrap_or_else(|e| panic!("{e}"));
    }

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

        // Check that the old operator was created at least MIGRATION_CAPACITY_INTERVAL ago
        // to prevent rapid empty operator migrations (spam prevention).
        let timestamp_created = Duration::from_nanos(timestamp_created_nanos);
        let now_duration = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH");

        if now_duration < timestamp_created + MIGRATION_CAPACITY_INTERVAL {
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
        // This is needed to not allow nodes to be transfered to different
        // locations with this feature.
        //
        // Transfering still must be done with redeployments.
        if old_node_operator_record.dc_id != new_node_operator_record.dc_id {
            return Err(MigrateError::DataCenterMismatch {
                old: old_node_operator_record.dc_id.clone(),
                new: new_node_operator_record.dc_id.clone(),
            });
        }

        // The caller must be the owner of both of the node operator
        // records.
        if caller.to_vec() != old_node_operator_record.node_provider_principal_id {
            return Err(MigrateError::CallerMismatch {
                caller,
                expected: PrincipalId(Principal::from_slice(
                    &old_node_operator_record.node_provider_principal_id,
                )),
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

    fn update_new_node_operator_record(
        old_node_operator_record: &NodeOperatorRecord,
        new_node_operator_record: &mut NodeOperatorRecord,
    ) {
        new_node_operator_record.node_allowance += old_node_operator_record.node_allowance;

        // In theory these should be the same for the same datacenter.
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

    fn get_node_mutations(
        &self,
        old_node_operator_id: PrincipalId,
        new_node_operator_id: PrincipalId,
    ) -> Vec<RegistryMutation> {
        get_node_operator_nodes_with_id(&self, old_node_operator_id)
            .into_iter()
            .map(|(key, record)| {
                upsert(
                    make_node_record_key(key).as_bytes(),
                    NodeRecord {
                        node_operator_id: new_node_operator_id.to_vec(),
                        ..record
                    }
                    .encode_to_vec(),
                )
            })
            .collect()
    }
}

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

#[derive(Debug, PartialEq, Eq)]
enum MigrateError {
    MissingInput,
    SamePrincipals,
    MissingNodeOperator {
        principal: PrincipalId,
    },
    NodeProviderMismatch {
        old: PrincipalId,
        new: PrincipalId,
    },
    DataCenterMismatch {
        old: String,
        new: String,
    },
    CallerMismatch {
        caller: PrincipalId,
        expected: PrincipalId,
    },
    OldOperatorRateLimit {
        principal: PrincipalId,
    },
}

impl Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MigrateError::MissingInput => "The provided payload has missing data".to_string(),
                MigrateError::SamePrincipals =>
                    "`new_operator_id` and `old_operator_id` must differ".to_string(),

                MigrateError::MissingNodeOperator { principal } =>
                    format!("Expected node operator {principal} to exist, but it doesn't"),
                MigrateError::NodeProviderMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are controlled by the same node provider. Instead got old node provider principal: {old}, new node provider principal: {new}"
                ),
                MigrateError::DataCenterMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are within the same data center. Instead got old data center: {old}, new data center: {new}"
                ),
                MigrateError::CallerMismatch { caller, expected } => format!(
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

    // Since seeding of test data takes place _now_
    // this is a helper to call the migration in the future
    // to avoid rate limits.
    //
    // This just masks the error as it calls the inner
    // function with a different _now_. Proper testing
    // of this rate limit cannot be done within unit
    // tests as `maybe_apply_mutation_internal` doesn't
    // provide an api for "now" and uses system time
    // which is hard to mock.
    fn now_plus_13_hours() -> SystemTime {
        let now = now_system_time();

        now + Duration::from_secs(13 * 60 * 60)
    }

    #[test]
    fn invalid_payloads() {
        let mut registry = Registry::new();

        for (payload, expected_err) in invalid_payloads_with_expected_errors() {
            let output = registry.migrate_node_operator_inner(
                payload,
                PrincipalId::new_user_test_id(1),
                now_plus_13_hours(),
            );

            let expected: Result<(), MigrateError> = Err(expected_err);
            assert_eq!(
                output, expected,
                "Expected: {expected:?} but found result: {output:?}"
            );
        }
    }

    #[test]
    fn missing_old_node_operator() {
        let mut registry = Registry::new();

        let payload = MigrateNodeOperatorPayload {
            old_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
            new_node_operator_id: Some(PrincipalId::new_user_test_id(2)),
        };

        let expected_err: Result<(), MigrateError> = Err(MigrateError::MissingNodeOperator {
            principal: payload.old_node_operator_id.unwrap(),
        });

        let resp = registry.migrate_node_operator_inner(
            payload,
            PrincipalId::new_user_test_id(3),
            now_plus_13_hours(),
        );

        assert_eq!(resp, expected_err);
    }

    #[test]
    fn node_provider_mismatch() {
        let mut registry = Registry::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let old_node_provider_id = PrincipalId::new_user_test_id(3);
        let new_node_provider_id = PrincipalId::new_user_test_id(4);

        let mutations = vec![
            upsert(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: old_node_operator_id.to_vec(),
                    node_provider_principal_id: old_node_provider_id.to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                NodeOperatorRecord {
                    node_operator_principal_id: new_node_operator_id.to_vec(),
                    node_provider_principal_id: new_node_provider_id.to_vec(),
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

        let expected_err: Result<(), MigrateError> = Err(MigrateError::NodeProviderMismatch {
            old: old_node_provider_id,
            new: new_node_provider_id,
        });

        let resp = registry.migrate_node_operator_inner(
            payload,
            PrincipalId::new_user_test_id(999),
            now_plus_13_hours(),
        );

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

        let expected_err: Result<(), MigrateError> =
            Err(MigrateError::DataCenterMismatch { old: dc1, new: dc2 });

        let resp = registry.migrate_node_operator_inner(
            payload,
            PrincipalId::new_user_test_id(999),
            now_plus_13_hours(),
        );

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

        let expected_err: Result<(), MigrateError> = Err(MigrateError::CallerMismatch {
            caller,
            expected: node_provider_id,
        });

        let resp = registry.migrate_node_operator_inner(payload, caller, now_plus_13_hours());

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

    struct TestSetup {
        nodes: Vec<NodeInformation>,
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
            allowance: u64,
            dc: &str,
            rewardable_nodes: Vec<(String, u32)>,
            max_rewardable_nodes: Vec<(String, u32)>,
        ) {
            let node_operator_record = NodeOperatorRecord {
                node_operator_principal_id: node_operator_id.to_vec(),
                node_allowance: allowance,
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

        fn fetch_nodes_added_for_node_operator(
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
        let mut setup = TestSetup::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let caller = PrincipalId::new_user_test_id(999);

        // Operator spec variables
        let rewardable_nodes = vec![
            (NodeRewardType::Type1.to_string(), 5),
            (NodeRewardType::Type2.to_string(), 10),
        ];
        let allowance = 5;
        let dc = "dc";

        setup.add_node_operator(
            old_node_operator_id,
            caller,
            allowance,
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

        setup
            .registry
            .migrate_node_operator_inner(payload, caller, now_plus_13_hours())
            .unwrap();

        // Ensure that the new operator is there
        let new_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(new_node_operator_id);

        // Ensure that the values are inherited from the old record
        assert_eq!(
            new_node_operator_record.node_provider_principal_id,
            caller.to_vec()
        );
        assert_eq!(new_node_operator_record.node_allowance, allowance);
        assert_eq!(
            new_node_operator_record.rewardable_nodes,
            rewardable_nodes.clone().into_iter().collect()
        );
        assert_eq!(
            new_node_operator_record.max_rewardable_nodes,
            rewardable_nodes.into_iter().collect()
        );
        assert_eq!(new_node_operator_record.dc_id, dc.to_string());

        // Ensure that the old operator isn't there
        let old_node_operator_record = setup.registry.get(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            setup.registry.latest_version(),
        );
        assert!(old_node_operator_record.is_none());

        // Ensure that the nodes owned by the old operator show the new operator now
        let nodes = setup.fetch_nodes_added_for_node_operator(old_node_operator_id);
        for node in nodes {
            assert_eq!(node.node_operator_id, new_node_operator_id.to_vec());
        }

        // Ensure that the extra nodes weren't touched
        let nodes = setup.fetch_nodes_added_for_node_operator(extra_node_operator);
        for node in nodes {
            assert_eq!(node.node_operator_id, extra_node_operator.to_vec());
        }

        // Validate number of mutations and their keys, values are checked above
        let changes = setup
            .registry
            .get_changes_since(setup.registry.latest_version() - 1, None);

        assert_eq!(changes.len(), 5);

        // Node changes
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

    fn filter_changes_for_key_prefix(
        prefix: &str,
        deltas: &Vec<HighCapacityRegistryDelta>,
    ) -> Vec<HighCapacityRegistryDelta> {
        deltas
            .iter()
            .filter(|delta| delta.key.starts_with(prefix.as_bytes()))
            .cloned()
            .collect()
    }

    #[test]
    fn successful_migration_when_new_operator_exist() {
        let mut setup = TestSetup::new();

        let old_node_operator_id = PrincipalId::new_user_test_id(1);
        let new_node_operator_id = PrincipalId::new_user_test_id(2);

        let caller = PrincipalId::new_user_test_id(999);

        // Old Operator spec variables
        let rewardable_nodes = vec![
            (NodeRewardType::Type1.to_string(), 5),
            (NodeRewardType::Type2.to_string(), 10),
        ];
        let allowance = 5;
        let dc = "dc";

        setup.add_node_operator(
            old_node_operator_id,
            caller,
            allowance,
            dc,
            rewardable_nodes.clone(),
            rewardable_nodes.clone(),
        );
        // Add nodes owned by the old node operator under test
        for _ in 0..3 {
            setup.add_node(old_node_operator_id);
        }

        // New operator spec variables
        let new_rewardable_nodes = vec![(NodeRewardType::Type1.to_string(), 1)];
        let new_allowance = 5;

        setup.add_node_operator(
            new_node_operator_id,
            caller,
            new_allowance,
            dc,
            new_rewardable_nodes.clone(),
            new_rewardable_nodes.clone(),
        );
        // Add nodes owned by the new node operator under test
        for _ in 0..4 {
            setup.add_node(new_node_operator_id);
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

        setup
            .registry
            .migrate_node_operator_inner(payload, caller, now_plus_13_hours())
            .unwrap();

        // Ensure that the new operator is there
        let new_node_operator_record = setup
            .registry
            .get_node_operator_or_panic(new_node_operator_id);

        // Ensure that the values are inherited from the old record
        assert_eq!(
            new_node_operator_record.node_provider_principal_id,
            caller.to_vec()
        );
        assert_eq!(
            new_node_operator_record.node_allowance,
            allowance + new_allowance
        );
        let rewardable_nodes: BTreeMap<_, _> = rewardable_nodes.into_iter().collect();
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
        assert_eq!(new_node_operator_record.dc_id, dc.to_string());

        // Ensure that the old operator isn't there
        let old_node_operator_record = setup.registry.get(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            setup.registry.latest_version(),
        );
        assert!(old_node_operator_record.is_none());

        // Ensure that the nodes owned by the old operator show the new operator now
        let nodes = setup.fetch_nodes_added_for_node_operator(old_node_operator_id);
        for node in nodes {
            assert_eq!(node.node_operator_id, new_node_operator_id.to_vec());
        }
        // Ensure that the nodes owned by the new operator still are owned by the
        // same node operator
        let nodes = setup.fetch_nodes_added_for_node_operator(new_node_operator_id);
        for node in nodes {
            assert_eq!(node.node_operator_id, new_node_operator_id.to_vec());
        }

        // Ensure that the extra nodes weren't touched
        let nodes = setup.fetch_nodes_added_for_node_operator(extra_node_operator);
        for node in nodes {
            assert_eq!(node.node_operator_id, extra_node_operator.to_vec());
        }

        // Validate number of mutations and their keys, values are checked above
        let changes = setup
            .registry
            .get_changes_since(setup.registry.latest_version() - 1, None);

        assert_eq!(changes.len(), 5);

        // Node changes
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
        expected: BTreeMap<String, u32>,
        old: BTreeMap<String, u32>,
        new: BTreeMap<String, u32>,
    ) {
        let mut new_mut = new;
        let mut old_mut = old;

        for (expected_key, expected_value) in expected.iter() {
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

        let caller = PrincipalId::new_user_test_id(999);
        registry.maybe_apply_mutation_internal(vec![upsert(
            make_node_operator_record_key(old_node_operator_id).as_bytes(),
            NodeOperatorRecord {
                node_operator_principal_id: old_node_operator_id.to_vec(),
                node_provider_principal_id: caller.to_vec(),
                dc_id: "dc".to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        )]);

        let payload = MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_node_operator_id),
            old_node_operator_id: Some(old_node_operator_id),
        };

        let resp = registry.migrate_node_operator_inner(payload.clone(), caller, now_system_time());
        let expected_err: Result<(), MigrateError> = Err(MigrateError::OldOperatorRateLimit {
            principal: old_node_operator_id,
        });

        assert_eq!(resp, expected_err);

        let resp = registry.migrate_node_operator_inner(payload, caller, now_plus_13_hours());

        assert!(resp.is_ok());
    }

    #[test]
    fn migrate_whole_data_center_to_one_node_operator() {
        let mut setup = TestSetup::new();

        let caller = PrincipalId::new_user_test_id(999);
        let dc = "dc";

        let old_node_operators: Vec<_> = (1..=3)
            .map(|no| PrincipalId::new_user_test_id(no))
            .collect();

        let node_allowance_per_node_operator = 5;
        let rewardable_nodes_type_1_per_operator = 3;
        let rewardable_nodes_per_node_operator: Vec<_> = vec![(
            NodeRewardType::Type1.to_string(),
            rewardable_nodes_type_1_per_operator,
        )];

        for node_operator in &old_node_operators {
            setup.add_node_operator(
                *node_operator,
                caller,
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

        for old_node_operator in &old_node_operators {
            let payload = MigrateNodeOperatorPayload {
                old_node_operator_id: Some(*old_node_operator),
                new_node_operator_id: Some(destination_node_operator),
            };

            let resp =
                setup
                    .registry
                    .migrate_node_operator_inner(payload, caller, now_plus_13_hours());
            assert!(resp.is_ok());
        }

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
        // let expected_err: Result<(), MigrateError> = Err(MigrateError::OldOperatorRateLimit {
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

            assert!(maybe_record.is_none());

            // Validate that all of the nodes have been moved to the new node operator
            for node in setup.fetch_nodes_added_for_node_operator(*old_node_operator) {
                assert_eq!(node.node_operator_id, destination_node_operator.to_vec());
            }
        }

        // Validate correct aggregation in the new node operator
        let record = setup
            .registry
            .get_node_operator_or_panic(destination_node_operator);

        assert_eq!(record.node_provider_principal_id, caller.to_vec());
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
