use crate::{
    common::LOG_PREFIX,
    invariants::{
        common::RegistrySnapshot, endpoint::check_endpoint_invariants,
        node_operator::check_node_operator_invariants,
        replica_version::check_replica_version_invariants,
        routing_table::check_routing_table_invariants, subnet::check_subnet_invariants,
    },
    mutations::common::decode_registry_value,
    registry::Registry,
};

use ic_protobuf::registry::conversion_rate::v1::IcpXdrConversionRateRecord;
use ic_registry_keys::make_icp_xdr_conversion_rate_record_key;
use ic_registry_transport::pb::v1::{registry_mutation::Type, RegistryMutation};

impl Registry {
    pub fn check_global_invariants(&self, mutations: &[RegistryMutation]) {
        println!("{}check_global_invariants: {:?}", LOG_PREFIX, mutations);

        let snapshot = self.take_latest_snapshot_with_mutations(mutations);

        // Conversion Rate invariants
        self.check_conversion_rate_invariants(&snapshot);

        // Node invariants
        // TODO(NNS1-202): re-enable this check when cd hourly test issues are sorted
        // out.

        // if let Err(e) = check_node_crypto_keys_invariants(&snapshot) {
        //     // TODO(NNS1-202): `expect` or `panic!` instead of `println!`
        //    println!("{}check_node_crypto_keys_invariants: {}", LOG_PREFIX, e)
        // }

        // Node Operator invariants
        let mut result = check_node_operator_invariants(&snapshot, false);

        // Routing Table invariants
        result = result.and(check_routing_table_invariants(&snapshot));

        // Subnet invariants
        result = result.and(check_subnet_invariants(&snapshot));

        // Replica version invariants
        result = result.and(check_replica_version_invariants(&snapshot, false));

        // Endpoint invariants
        result = result.and(check_endpoint_invariants(&snapshot, false));

        if let Err(e) = result {
            panic!(
                "{} invariant check failed with message:{}",
                LOG_PREFIX, e.msg
            );
        }
    }

    /// If there is a proposal for a new conversion rate, the function makes
    /// sure that the timestamp of the proposed conversion rate record is
    /// larger than the current timestamp in the current record.
    fn check_conversion_rate_invariants(&self, snapshot: &RegistrySnapshot) {
        // Check if there is a conversion rate in the mutated snapshot:
        if let Some(proposed_conversion_rate_bytes) =
            snapshot.get(&make_icp_xdr_conversion_rate_record_key().into_bytes())
        {
            // Decode the proposed conversion rate:
            let proposed_conversion_rate = decode_registry_value::<IcpXdrConversionRateRecord>(
                proposed_conversion_rate_bytes.clone(),
            );
            // Assert that the rate is positive (this is an additional sanity check as the
            // rate should always be at least `minimum_icp_xdr_rate`):
            assert!(proposed_conversion_rate.xdr_permyriad_per_icp > 0);
            // Check if there is a conversion rate in the registry (without mutations):
            if let Some(conversion_rate_bytes) = self.get(
                &make_icp_xdr_conversion_rate_record_key().into_bytes(),
                self.latest_version(),
            ) {
                // Decode the current conversion rate:
                let conversion_rate = decode_registry_value::<IcpXdrConversionRateRecord>(
                    conversion_rate_bytes.clone().value,
                );
                // Assert that the records are equal, i.e., there is no mutation, or the
                // timestamp is larger in the proposed conversion rate:
                assert!(
                    proposed_conversion_rate == conversion_rate
                        || proposed_conversion_rate.timestamp_seconds
                            > conversion_rate.timestamp_seconds
                );
            }
        }
    }

    fn take_latest_snapshot_with_mutations(
        &self,
        mutations: &[RegistryMutation],
    ) -> RegistrySnapshot {
        let mut snapshot = self.take_latest_snapshot();
        for mutation in mutations.iter() {
            let key = &mutation.key;
            match Type::from_i32(mutation.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => {
                    snapshot.insert(key.to_vec(), mutation.value.clone());
                }
                Type::Delete => {
                    snapshot.remove(&key.to_vec());
                }
            }
        }
        snapshot
    }

    fn take_latest_snapshot(&self) -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot::new();

        for (key, values) in self.store.iter() {
            let registry_value = values.back().unwrap();
            if !registry_value.deletion_marker {
                snapshot.insert(key.to_vec(), registry_value.value.clone());
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_nns_common::registry::encode_or_panic;
    use ic_nns_constants::ids::TEST_USER1_PRINCIPAL;
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::{
        node_operator::v1::NodeOperatorRecord, routing_table::v1::RoutingTable,
    };
    use ic_registry_keys::{make_node_operator_record_key, make_routing_table_record_key};
    use ic_registry_transport::{delete, insert, pb::v1::RegistryMutation};

    /// Shorthand to try a mutation
    fn try_mutate(registry: &mut Registry, mutations: &[RegistryMutation]) {
        registry.maybe_apply_mutation_internal(mutations.to_vec())
    }

    #[test]
    #[should_panic(expected = "No routing table in snapshot")]
    fn routing_table_invariants_do_not_hold() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });
        let registry = Registry::new();
        let mutation = vec![insert(key.as_bytes(), &value)];
        registry.check_global_invariants(&mutation);
    }

    /// This helper function creates a valid registry.
    fn create_valid_registry() -> Registry {
        let mut registry = Registry::new();
        try_mutate(&mut registry, &invariant_compliant_mutation());
        registry
    }

    #[test]
    fn snapshot_reflects_latest_registry_state() {
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&RoutingTable { entries: vec![] });

        let key2 = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value2 = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });

        let mutations = vec![
            insert(key1.as_bytes(), &value1),
            insert(key2.as_bytes(), &value2),
        ];
        let snapshot = Registry::new().take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(key1.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value1);

        let snapshot_data = snapshot.get(key2.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value2);
    }

    #[test]
    fn snapshot_data_are_updated() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });
        let mut mutations = vec![insert(key.as_bytes(), &value)];

        let registry = Registry::new();
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value);

        mutations.append(&mut vec![delete(key.as_bytes())]);
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);
        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_none());
    }

    #[test]
    /// The test ensures that the conversion rate proposal passes the invariants
    /// check if a) there is currently no record in the registry or
    /// b) the proposal contains a timestamp that is larger than the timestamp
    /// of the conversion rate record in the registry.
    fn conversion_rate_invariant_valid_timestamp() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Create a conversion rate to be added to the snapshot:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 3141592,
            xdr_permyriad_per_icp: 123451234,
        };
        // Create a snapshot with the proposed conversion rate:
        let snapshot = registry.take_latest_snapshot_with_mutations(&[insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // The conversion rate invariants should be satisfied because there is no record
        // in the registry:
        registry.check_conversion_rate_invariants(&snapshot);

        // Manually add an initial rate with a smaller timestamp:
        let initial_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 1415926,
            xdr_permyriad_per_icp: 123451234,
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&initial_conversion_rate),
        )]);
        // The conversion rate invariants should still be satisfied:
        registry.check_conversion_rate_invariants(&snapshot);
    }

    #[test]
    /// The test ensures that the conversion rate proposal does not pass the
    /// invariants check if the proposal contains a timestamp that is
    /// smaller than the timestamp of the conversion rate record in the
    /// registry.
    #[should_panic]
    fn conversion_rate_invariant_invalid_timestamp() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Add an initial conversion rate:
        let initial_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 1000000,
            xdr_permyriad_per_icp: 2000000,
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&initial_conversion_rate),
        )]);
        // Create a conversion rate to be added to the snapshot:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 999999,
            xdr_permyriad_per_icp: 2000000,
        };
        // Get a snapshot with the proposed conversion rate:
        let snapshot = registry.take_latest_snapshot_with_mutations(&[insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // The conversion rate invariants should not be satisfied because the timestamp
        // in the proposal is smaller:
        registry.check_conversion_rate_invariants(&snapshot);
    }

    #[test]
    /// The test ensures that registry mutations not affecting the conversion
    /// rate are possible when a conversion rate is set in the registry.
    fn conversion_rate_invariant_unrelated_mutation() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Create a conversion rate to be added to the registry:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 3141592,
            xdr_permyriad_per_icp: 123451234,
        };
        // Add the conversion rate to the registry:
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // All global invariants should be satisfied when introducing an unrelated
        // mutation, e.g., resetting the routing table:
        registry.check_global_invariants(&[insert(
            make_routing_table_record_key(),
            encode_or_panic(&RoutingTable::default()),
        )]);
    }
}
