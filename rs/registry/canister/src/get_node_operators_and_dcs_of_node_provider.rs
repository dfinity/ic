use crate::registry::Registry;
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_data_center_record_key;
use ic_registry_keys::NODE_OPERATOR_RECORD_KEY_PREFIX;
use ic_types::PrincipalId;
use std::convert::TryFrom;
use std::str::from_utf8;

impl Registry {
    ///Return a vector of Data Center - Node Operator pairs for a given node provider.
    pub fn get_node_operators_and_dcs_of_node_provider(
        &self,
        node_provider: PrincipalId,
    ) -> Result<Vec<(DataCenterRecord, NodeOperatorRecord)>, String> {
        let mut node_operators_and_dcs_of_node_provider: Vec<(
            DataCenterRecord,
            NodeOperatorRecord,
        )> = vec![];
        for (key, values) in self.store.iter() {
            if key.starts_with(NODE_OPERATOR_RECORD_KEY_PREFIX.as_bytes()) {
                let value = values.back().unwrap();
                if value.deletion_marker {
                    continue;
                }
                let node_operator = decode_or_panic::<NodeOperatorRecord>(value.value.clone());
                let node_provider_id = PrincipalId::try_from(
                    &node_operator.node_provider_principal_id,
                )
                .map_err(|e| {
                    format!(
                        "Node Operator with key '{:?}' has a node_provider_principal_id \
                                 that cannot be parsed as a PrincipalId: '{}'",
                        from_utf8(key.as_slice()),
                        e
                    )
                })?;
                if node_provider_id != node_provider {
                    continue;
                }
                let dc_id = node_operator.dc_id.clone();
                let dc_key = make_data_center_record_key(&dc_id);
                let dc_record_bytes = self
                    .get(dc_key.as_bytes(), self.latest_version())
                    .ok_or_else(|| {
                        format!(
                            "Node Operator with key '{:?}' has data center ID '{}' \
                            not found in the Registry",
                            from_utf8(key.as_slice()),
                            dc_id
                        )
                    })?
                    .value
                    .clone();
                let data_center = decode_or_panic::<DataCenterRecord>(dc_record_bytes);
                node_operators_and_dcs_of_node_provider
                    .push((data_center.clone(), node_operator.clone()));
            }
        }
        Ok(node_operators_and_dcs_of_node_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::dc::v1::AddOrRemoveDataCentersProposalPayload;
    use ic_registry_keys::make_node_operator_record_key;
    use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
    use maplit::btreemap;
    use std::collections::HashSet;
    use std::hash::Hash;

    pub fn principal(i: u64) -> PrincipalId {
        PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap()
    }

    // Check that two vectors have the same elements. If fails if two vectors have a different
    // amount of repeated elements, but that is fine in this case, as we shouldn't have repeated
    // NodeOperator or DataCenter records.
    fn vec_equal_elements<T: Eq + Hash>(i1: Vec<T>, i2: Vec<T>) -> bool {
        let set: HashSet<&T> = i2.iter().collect();
        i2.len() == i1.len() && i1.into_iter().all(|x| set.contains(&x))
    }

    // DataCenterRecord cannot implement Eq because of the Gps field being float, in the following
    // tests we assume that the presence of the Gps field is not important for the functionality
    // being tested and use this struct to compare the results of the tests with their expected results.
    #[derive(PartialEq, Eq, Hash)]
    struct DataCenterNoGps {
        id: String,
        region: String,
        owner: String,
    }

    impl From<DataCenterRecord> for DataCenterNoGps {
        fn from(data_center_record: DataCenterRecord) -> DataCenterNoGps {
            DataCenterNoGps {
                id: data_center_record.id.clone(),
                region: data_center_record.region.clone(),
                owner: data_center_record.owner,
            }
        }
    }

    fn remove_gps_from_data_center_records(
        in_vec: Vec<(DataCenterRecord, NodeOperatorRecord)>,
    ) -> Vec<(DataCenterNoGps, NodeOperatorRecord)> {
        in_vec
            .into_iter()
            .map(|(data_center_record, node_operator_record)| {
                (
                    DataCenterNoGps::from(data_center_record),
                    node_operator_record,
                )
            })
            .collect()
    }

    /// Assert that 'get_node_operators_and_dcs_of_node_provider' returns the expected values.
    /// First creates a mock registry with 4 NodeOperatorRecord and 3 DataCenterRecord belonging to
    /// two different node providers, and then checks that querying for each of the two node
    /// provider principals returns the expected values.
    #[test]
    fn test_get_node_operators_and_dcs_of_node_provider() {
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation());

        // Node Provider 1
        let dc_id_1: String = "NY1".into();
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal(1)),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: dc_id_1.clone(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };
        let node_operator_1 = NodeOperatorRecord::from(node_operator_payload.clone());
        registry.do_add_node_operator(node_operator_payload);
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal(2)),
            node_allowance: 6,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: dc_id_1.clone(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };
        let node_operator_2 = NodeOperatorRecord::from(node_operator_payload.clone());
        registry.do_add_node_operator(node_operator_payload);
        let data_center_1 = DataCenterRecord {
            id: dc_id_1,
            region: "region1".into(),
            owner: "owner1".into(),
            gps: None,
        };

        let dc_id_2: String = "ZH1".into();
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal(3)),
            node_allowance: 7,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: dc_id_2.clone(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };
        let node_operator_3 = NodeOperatorRecord::from(node_operator_payload.clone());
        registry.do_add_node_operator(node_operator_payload);
        let data_center_2 = DataCenterRecord {
            id: dc_id_2,
            region: "region2".into(),
            owner: "owner2".into(),
            gps: None,
        };

        // Node provider 2
        let dc_id_3: String = "LA1".into();
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal(4)),
            node_allowance: 7,
            node_provider_principal_id: Some(*TEST_USER2_PRINCIPAL),
            dc_id: dc_id_3.clone(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };
        let node_operator_4 = NodeOperatorRecord::from(node_operator_payload.clone());
        registry.do_add_node_operator(node_operator_payload);
        let data_center_3 = DataCenterRecord {
            id: dc_id_3,
            region: "region3".into(),
            owner: "owner3".into(),
            gps: None,
        };

        let add_data_center_payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![
                data_center_1.clone(),
                data_center_2.clone(),
                data_center_3.clone(),
            ],
            data_centers_to_remove: vec![],
        };
        registry.do_add_or_remove_data_centers(add_data_center_payload);

        let expected_1 = vec![
            (data_center_1.clone(), node_operator_1),
            (data_center_1, node_operator_2),
            (data_center_2, node_operator_3),
        ];
        assert!(vec_equal_elements(
            remove_gps_from_data_center_records(
                registry
                    .get_node_operators_and_dcs_of_node_provider(*TEST_USER1_PRINCIPAL)
                    .unwrap()
            ),
            remove_gps_from_data_center_records(expected_1)
        ));

        let expected_2 = vec![(data_center_3, node_operator_4)];
        assert!(vec_equal_elements(
            remove_gps_from_data_center_records(
                registry
                    .get_node_operators_and_dcs_of_node_provider(*TEST_USER2_PRINCIPAL)
                    .unwrap()
            ),
            remove_gps_from_data_center_records(expected_2)
        ));
    }

    /// Tests the case where node providers have been removed.
    #[test]
    fn test_get_node_operators_and_dcs_of_node_provider_empty() {
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation());

        let dc_id_1: String = "NY1".into();
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal(1)),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: dc_id_1.clone(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };
        // Add node operator.
        registry.do_add_node_operator(node_operator_payload);
        let data_center_1 = DataCenterRecord {
            id: dc_id_1,
            region: "region1".into(),
            owner: "owner1".into(),
            gps: None,
        };

        let add_data_center_payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![data_center_1],
            data_centers_to_remove: vec![],
        };
        registry.do_add_or_remove_data_centers(add_data_center_payload);
        let key = make_node_operator_record_key(principal(1)).into_bytes();

        // Remove node operator.
        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Delete as i32,
            key,
            value: vec![],
        }];

        // Check invariants before applying mutations
        registry.maybe_apply_mutation_internal(mutations);

        assert!(registry
            .get_node_operators_and_dcs_of_node_provider(*TEST_USER1_PRINCIPAL)
            .unwrap()
            .is_empty());
    }
}
