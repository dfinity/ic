use crate::certification::recertify_registry;
use crate::{pb::v1::RegistryCanisterStableStorage, registry::Registry};
use ic_base_types::PrincipalId;
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use maplit::btreemap;
use prost::Message;
use std::str::FromStr;

pub fn canister_post_upgrade(
    registry: &mut Registry,
    registry_storage: RegistryCanisterStableStorage,
) {
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.

    registry.from_serializable_form(
        registry_storage
            .registry
            .expect("Error decoding from stable"),
    );

    // Registry data migrations should be implemented as follows:
    let mutation_batches_due_to_data_migrations = {
        let mutations = fix_node_operators_corrupted(registry);
        if mutations.is_empty() {
            0 // No mutations required for this data migration.
        } else {
            registry.maybe_apply_mutation_internal(mutations);
            1 // Single batch of mutations due to this data migration.
        }
    };
    //
    // When there are no migrations, `mutation_batches_due_to_data_migrations` should be set to `0`.
    // let mutation_batches_due_to_data_migrations = 0;

    registry.check_global_state_invariants(&[]);
    // Registry::from_serializable_from guarantees this always passes in this function
    // because it fills in missing versions to maintain that invariant
    registry.check_changelog_version_invariants();

    // This is no-op outside Canister environment, and is therefore not under unit-test coverage
    recertify_registry(registry);

    // ANYTHING BELOW THIS LINE SHOULD NOT MUTATE STATE

    if registry_storage.pre_upgrade_version.is_some() {
        let pre_upgrade_version = registry_storage.pre_upgrade_version.unwrap();

        assert_eq!(
            pre_upgrade_version + mutation_batches_due_to_data_migrations,
            registry.latest_version(),
            "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: {:?}, Last version: {:?}",
            pre_upgrade_version,
            registry.latest_version()
        );
    }
}

fn fix_node_operators_corrupted(registry: &Registry) -> Vec<RegistryMutation> {
    ic_cdk::println!("Fixing corrupted Node Operator records...");
    let create_node_operator_mutation =
        |principal_id_str: &str,
         modify_record: fn(&mut NodeOperatorRecord, PrincipalId)|
         -> Result<RegistryMutation, String> {
            let node_operator_id = PrincipalId::from_str(principal_id_str)
                .map_err(|e| format!("Failed to parse principal ID {}: {}", principal_id_str, e))?;

            let registry_value = registry
                .get(
                    make_node_operator_record_key(node_operator_id).as_bytes(),
                    registry.latest_version(),
                )
                .ok_or(format!(
                    "Failed to find NodeOperatorRecord for operator {}",
                    node_operator_id
                ))?;

            let mut record =
                NodeOperatorRecord::decode(registry_value.value.as_slice()).map_err(|e| {
                    format!(
                        "Failed to decode NodeOperatorRecord for operator {}: {}",
                        node_operator_id, e
                    )
                })?;

            modify_record(&mut record, node_operator_id);

            Ok(update(
                make_node_operator_record_key(node_operator_id),
                record.encode_to_vec(),
            ))
        };

    let mut mutations = Vec::new();

    // 3nu7r - ujq4k -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        "3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
            record.max_rewardable_nodes = btreemap! {
                NodeRewardType::Type1dot1.to_string() => 19
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for 3nu7r: {}", e),
    }

    match create_node_operator_mutation(
        "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        // Dummy mutation that should just increase the version and get the updates
        |_record, _| {},
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for ujq4k: {}", e),
    }

    // bmlhw - spsu4 -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        "bmlhw-kinr6-7cyv5-3o3v6-ic6tw-pnzk3-jycod-6d7sw-owaft-3b6k3-kqe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
            record.max_rewardable_nodes = btreemap! {
                NodeRewardType::Type1.to_string() => 14
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for bmlhw: {}", e),
    }

    match create_node_operator_mutation(
        "spsu4-5hl4t-bfubp-qvoko-jprw4-wt7ou-nlnbk-gb5ib-aqnoo-g4gl6-kae",
        |record, _| {},
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for spsu4: {}", e),
    }

    // redpf - 2rqo7 -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        "redpf-rrb5x-sa2it-zhbh7-q2fsp-bqlwz-4mf4y-tgxmj-g5y7p-ezjtj-5qe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for redpf: {}", e),
    }

    match create_node_operator_mutation(
        "2rqo7-ot2kv-upof3-odw3y-sjckb-qeibt-n56vj-7b4pt-bvrtg-zay53-4qe",
        |record, _| {
            record.rewardable_nodes = btreemap! {
                NodeRewardType::Type1dot1.to_string() => 28
            };
            record.max_rewardable_nodes = btreemap! {
                NodeRewardType::Type1dot1.to_string() => 28
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for 2rqo7: {}", e),
    }

    mutations
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::test_helpers::{empty_mutation, invariant_compliant_registry},
        registry::{EncodedVersion, Version},
        registry_lifecycle::Registry,
    };
    use ic_base_types::PrincipalId;
    use ic_registry_transport::insert;
    use maplit::btreemap;
    use std::str::FromStr;

    fn stable_storage_from_registry(
        registry: &Registry,
        override_version: Option<Version>,
    ) -> Vec<u8> {
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: Some(registry.serializable_form()),
            pre_upgrade_version: override_version.or_else(|| Some(registry.latest_version())),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");
        serialized
    }

    #[test]
    fn post_upgrade_succeeds_with_valid_registry() {
        // given valid registry state encoded for stable storage
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // we can use canister_post_upgrade to initialize a new registry correctly
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // and the version is right
        assert_eq!(new_registry.latest_version(), 1);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable.")]
    fn post_upgrade_fails_when_stable_storage_fails_decoding() {
        let mut registry = Registry::new();
        // try with garbage to check first error condition
        let stable_storage_bytes = [1, 2, 3];
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable")]
    fn post_upgrade_fails_when_registry_missing_from_storage() {
        // Given stable storage that's missing a registry
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: None,
            pre_upgrade_version: Some(1u64),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");

        let mut registry = Registry::new();

        // When we try to run canister_post_upgrade
        // Then we panic
        let registry_storage = RegistryCanisterStableStorage::decode(serialized.as_slice())
            .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "[Registry] invariant check failed with message: no system subnet")]
    fn post_upgrade_fails_on_global_state_invariant_check_failure() {
        // We only check a single failure mode here,
        // since the rest should be under other test coverage
        let registry = Registry::new();
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // with our bad mutation, this should throw
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }

    #[test]
    fn post_upgrade_fills_in_missing_versions_to_maintain_invariant() {
        // We only check a single failure mode, since the rest should be under other test coverage
        let mut registry = invariant_compliant_registry(0);
        registry
            .changelog
            .insert(EncodedVersion::from(7), empty_mutation());
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(7u64));

        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // missing versions are added by the deserializer
        let mut sorted_changelog_versions = new_registry
            .changelog()
            .iter()
            .map(|(encoded_version, _)| encoded_version.as_version())
            .collect::<Vec<u64>>();
        sorted_changelog_versions.sort_unstable();
        // we expect all intermediate versions to be present
        assert_eq!(sorted_changelog_versions, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    #[should_panic(
        expected = "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: 100, Last version: 1"
    )]
    fn post_upgrade_fails_when_registry_decodes_different_version() {
        // Given a mismatched stable storage version from the registry
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(100u64));
        // then we panic when decoding
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }

    #[test]
    fn test_fix_all_and_only_node_operators_corrupted() {
        let mut registry = invariant_compliant_registry(0);
        let mut node_operator_additions = Vec::new();

        // This is a good record that should be left untouched
        let node_operator_good = PrincipalId::from_str(
            "2aemz-63apz-bds45-nypax-oj52g-fyl6i-sjhtv-ysu5t-hqvve-ygtcr-yae",
        )
        .unwrap();
        let record_good = NodeOperatorRecord {
            node_operator_principal_id: node_operator_good.to_vec(),
            dc_id: "dummy_dc_id_1".to_string(),
            ipv6: Some("dummy_ipv6_1".to_string()),
            max_rewardable_nodes: btreemap! { "type3.1".to_string() => 6},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_good),
            record_good.encode_to_vec(),
        ));

        // 3nu7r is corrupted and should be fixed
        let node_operator_3nu7r_k = PrincipalId::from_str(
            "3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe",
        )
        .unwrap();
        let node_operator_3nu7r_v = PrincipalId::from_str(
            "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        )
        .unwrap();
        let record_3nu7r = NodeOperatorRecord {
            node_operator_principal_id: node_operator_3nu7r_v.to_vec(),
            dc_id: "dummy_dc_id_3nu7r".to_string(),
            ipv6: Some("dummy_ipv6_3nu7r".to_string()),
            // Empty max rewardable nodes, should be filled in by the migration
            max_rewardable_nodes: btreemap! {},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_3nu7r_k),
            record_3nu7r.encode_to_vec(),
        ));

        // spsu4 is corrupted and should be fixed
        let node_operator_spsu4 = PrincipalId::from_str(
            "spsu4-5hl4t-bfubp-qvoko-jprw4-wt7ou-nlnbk-gb5ib-aqnoo-g4gl6-kae",
        )
        .unwrap();
        let record_spsu4 = NodeOperatorRecord {
            node_operator_principal_id: node_operator_spsu4.to_vec(),
            dc_id: "dummy_dc_id_spsu4".to_string(),
            ipv6: Some("dummy_ipv6_spsu4".to_string()),
            // wrong rewardable nodes, should be fixed by the migration
            rewardable_nodes: btreemap! {"type1".to_string() => 14},
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 14},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_spsu4),
            record_spsu4.encode_to_vec(),
        ));

        // ujq4k is corrupted and should be fixed
        let node_operator_ujq4k = PrincipalId::from_str(
            "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        )
        .unwrap();
        let record_ujq4k = NodeOperatorRecord {
            node_operator_principal_id: node_operator_ujq4k.to_vec(),
            dc_id: "dummy_dc_id_ujq4k".to_string(),
            ipv6: Some("dummy_ipv6_ujq4k".to_string()),
            // wrong rewardable nodes, should be fixed by the migration
            rewardable_nodes: btreemap! {"type1.1".to_string() => 19},
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 9},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_ujq4k),
            record_ujq4k.encode_to_vec(),
        ));

        registry.apply_mutations_for_test(node_operator_additions);
        let mutations = fix_node_operators_corrupted(&registry);
        // We expect 2 fixes, one for each corrupted record
        assert_eq!(mutations.len(), 3);
        registry.apply_mutations_for_test(mutations);

        // Good record should be left untouched
        let record_good_got = registry.get_node_operator_or_panic(node_operator_good);
        let expected_record_good = record_good;
        assert_eq!(
            record_good_got, expected_record_good,
            "Assertion for NodeOperator good failed"
        );

        // 3nu7r should be fixed
        let record_3nu7r_got = registry.get_node_operator_or_panic(node_operator_3nu7r_k);
        let expected_record_3nu7r = NodeOperatorRecord {
            node_operator_principal_id: node_operator_3nu7r_k.to_vec(),
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 19},
            ..record_3nu7r
        };
        assert_eq!(
            record_3nu7r_got, expected_record_3nu7r,
            "Assertion for NodeOperator {node_operator_3nu7r_k} failed"
        );

        // spsu4 should be fixed
        let record_spsu4_got = registry.get_node_operator_or_panic(node_operator_spsu4);
        let expected_record_spsu4 = NodeOperatorRecord {
            node_operator_principal_id: node_operator_spsu4.to_vec(),
            rewardable_nodes: btreemap! {"type1.1".to_string() => 14},
            ..record_spsu4
        };
        assert_eq!(
            record_spsu4_got, expected_record_spsu4,
            "Assertion for NodeOperator {node_operator_3nu7r_k} failed"
        );

        // ujq4k should be fixed
        let record_ujq4k_got = registry.get_node_operator_or_panic(node_operator_ujq4k);
        let expected_record_ujq4k = NodeOperatorRecord {
            node_operator_principal_id: node_operator_ujq4k.to_vec(),
            rewardable_nodes: btreemap! {"type1.1".to_string() => 9},
            ..record_ujq4k
        };
        assert_eq!(
            record_ujq4k_got, expected_record_ujq4k,
            "Assertion for NodeOperator {node_operator_3nu7r_k} failed"
        );
    }
}
