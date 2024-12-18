use crate::{
    mutations::node_management::common::{get_key_family, get_key_family_iter},
    pb::v1::NodeProvidersMonthlyXdrRewards,
    registry::Registry,
};
use ic_protobuf::registry::{
    dc::v1::DataCenterRecord, node_operator::v1::NodeOperatorRecord,
    node_rewards::v2::NodeRewardsTable,
};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::calculate_rewards_v0;
use prost::Message;
use std::collections::BTreeMap;

impl Registry {
    /// Return a map from Node Provider IDs to the amount (in 10,000ths of an
    /// SDR) they should be rewarded for providing nodes to the Internet
    /// Computer for the month.
    pub fn get_node_providers_monthly_xdr_rewards(
        &self,
    ) -> Result<NodeProvidersMonthlyXdrRewards, String> {
        let mut rewards = NodeProvidersMonthlyXdrRewards::default();

        let rewards_table_bytes = self
            .get(NODE_REWARDS_TABLE_KEY.as_bytes(), self.latest_version())
            .ok_or_else(|| "Node Rewards Table was not found in the Registry".to_string())?
            .value
            .clone();

        let rewards_table = NodeRewardsTable::decode(rewards_table_bytes.as_slice()).unwrap();

        let node_operators =
            get_key_family::<NodeOperatorRecord>(self, NODE_OPERATOR_RECORD_KEY_PREFIX);

        let data_centers = get_key_family_iter::<DataCenterRecord>(self, DATA_CENTER_KEY_PREFIX)
            .collect::<BTreeMap<String, DataCenterRecord>>();

        let reward_values = calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)?;

        rewards.rewards = reward_values
            .rewards_per_node_provider
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        rewards.registry_version = Some(self.latest_version());

        Ok(rewards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;

    #[cfg(target_arch = "wasm32")]
    use dfn_core::println;
    use ic_nervous_system_common_test_keys::{
        TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL, TEST_USER4_PRINCIPAL,
    };
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::{
        dc::v1::AddOrRemoveDataCentersProposalPayload,
        node_rewards::v2::{
            NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload,
        },
    };
    use ic_registry_keys::make_node_operator_record_key;
    use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
    use ic_types::PrincipalId;
    use maplit::btreemap;
    use std::collections::BTreeMap;

    /// Assert that `get_node_providers_monthly_xdr_rewards` returns success in the case
    /// where deleted Node Operators exist.
    #[test]
    fn test_get_node_providers_monthly_xdr_rewards_ignores_deleted_keys() {
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation(0));

        // Add empty Node Rewards table to test failure cases
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::default();
        registry.do_update_node_rewards_table(node_rewards_payload);

        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_USER1_PRINCIPAL),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: "ny1".into(),
            rewardable_nodes: btreemap! {},
            ipv6: None,
        };

        registry.do_add_node_operator(node_operator_payload);

        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL).into_bytes();

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Delete as i32,
            key,
            value: vec![],
        }];

        // Check invariants before applying mutations
        registry.maybe_apply_mutation_internal(mutations);

        assert!(registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap()
            .rewards
            .is_empty());
    }

    fn registry_init_empty() -> Registry {
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation(0));

        // Assert get_node_providers_monthly_xdr_rewards fails because no rewards table
        // exists in the Registry
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert_eq!(&err, "Node Rewards Table was not found in the Registry");

        // Add empty Node Rewards table to test failure cases
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::default();
        registry.do_update_node_rewards_table(node_rewards_payload);

        registry
    }

    fn registry_add_data_center_for_node_provider(
        mut registry: Registry,
        owner: String,
        dc_id: String,
        dc_region: String,
    ) -> Registry {
        // Assert get_node_providers_monthly_xdr_rewards fails because the DC is not yet in the Registry
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert!(err.contains(&format!(
            "has data center ID '{}' not found in the Registry",
            dc_id.to_lowercase()
        )));

        // Add Data Centers
        let data_centers_to_add = vec![DataCenterRecord {
            id: dc_id,
            region: dc_region,
            owner,
            gps: None,
        }];

        let dc_payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add,
            data_centers_to_remove: vec![],
        };

        registry.do_add_or_remove_data_centers(dc_payload);

        registry
    }

    // A test utility function to add a new NP with a new DC
    fn registry_add_node_operator(
        mut registry: Registry,
        np_principal: PrincipalId,
        no_principal: PrincipalId,
        dc_id: String,
        dc_region: String,
        node_allowance: u64,
        rewardable_nodes: BTreeMap<String, u32>,
    ) -> Registry {
        let node_operator_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(no_principal),
            node_allowance,
            node_provider_principal_id: Some(np_principal),
            dc_id: dc_id.clone(),
            rewardable_nodes: rewardable_nodes.clone(),
            ipv6: None,
        };
        registry.do_add_node_operator(node_operator_payload);

        // In production the DC owner is an arbitrary string
        let dc_owner = np_principal
            .to_string()
            .split_once('-')
            .unwrap()
            .0
            .to_string();
        let registry =
            registry_add_data_center_for_node_provider(registry, dc_owner, dc_id, dc_region);

        // Assert get_node_providers_monthly_xdr_rewards defaults to 1 XDR per month per node
        // because there rewards table does not have an entry for the DC's region
        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();
        let np_monthly_rewards = monthly_rewards
            .rewards
            .get(&np_principal.to_string())
            .unwrap();
        if np_principal == no_principal {
            // In the tests below, this is the way we distinguish if a NP has more than one DC
            // NP's rewardable_nodes * 1 XDR/month/node
            assert_eq!(
                *np_monthly_rewards,
                rewardable_nodes.values().sum::<u32>() as u64
            );
        }

        registry
    }

    #[test]
    fn test_get_node_providers_monthly_xdr_rewards_gen1() {
        let registry = registry_init_empty();

        ///////////////////////////////
        // Adding two Node Providers without adding the rewards table yet
        ///////////////////////////////
        let np1 = *TEST_USER1_PRINCIPAL;
        let registry = registry_add_node_operator(
            registry,
            np1,
            np1,
            "NY1".to_string(),
            "North America,US,NY".into(),
            5,
            btreemap! { "type0".to_string() => 4, "type2".to_string() => 1 },
        );

        let np2 = *TEST_USER2_PRINCIPAL;
        let mut registry = registry_add_node_operator(
            registry,
            np2,
            np2,
            "ZH3".to_string(),
            "Europe,CH,Zurich".into(),
            18,
            btreemap! { "type0".to_string() => 11, "type2".to_string() => 7 },
        );

        // Add regions to rewards table (but an empty map to test failure cases)
        let new_entries = btreemap! {
            "North America,US".to_string() =>  NodeRewardRates {
                rates: btreemap!{}
            },
        };

        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload { new_entries };
        registry.do_update_node_rewards_table(node_rewards_payload);

        ///////////////////////////////
        // Assert get_node_providers_monthly_xdr_rewards still provides default values
        ///////////////////////////////
        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();
        let np1 = TEST_USER1_PRINCIPAL.to_string();
        let np1_rewards = monthly_rewards.rewards.get(&np1).unwrap();
        assert_eq!(*np1_rewards, 5); // 5 nodes at 1 XDR/month/node
        assert_eq!(
            monthly_rewards.registry_version,
            Some(registry.latest_version())
        );

        ///////////////////////////////
        // Now add the reward table for type0 and type2 nodes and check that the values are properly used
        ///////////////////////////////
        let json = r#"{
            "North America,US,NY":         { "type0": [240, null]                                                          },
            "North America,US":            { "type0": [677, null],  "type2": [456, null]                                   },
            "North America":               { "type0": [801, null]                                                          },
            "Europe":                      { "type0": [68, null],   "type2": [11, null]                                    }
        }"#;

        let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
            serde_json::from_str(json).unwrap();
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
        registry.do_update_node_rewards_table(node_rewards_payload);

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();

        // NP1: 4 'type0' nodes in 'North America,US,NY' + 1 'type2' node in 'North America,US'
        assert_eq!(
            *monthly_rewards.rewards.get(&np1.to_string()).unwrap(),
            (4 * 240) + 456
        );
        // NP2: 11 'type0' nodes in 'Europe,CH,Zurich' + 7 'type2' nodes in 'CH'
        assert_eq!(
            *monthly_rewards.rewards.get(&np2.to_string()).unwrap(),
            (11 * 68) + (7 * 11)
        );

        ///////////////////////////////
        // Now add the reward table entries for type3 rewards and confirm nothing changes for type0 and type2 nodes
        ///////////////////////////////
        let json = r#"{
            "North America,US,NY":         { "type3": [111, null] },
            "North America,US":            { "type3": [222, null] },
            "North America":               { "type3": [333, null] },
            "Europe":                      { "type3": [444, null] },
            "Asia":                        { "type3": [555, null] }
        }"#;

        let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
            serde_json::from_str(json).unwrap();
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
        registry.do_update_node_rewards_table(node_rewards_payload);

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();

        // NP1: 4 'type0' nodes in 'North America,US,NY' + 1 'type2' node in 'North America,US'
        assert_eq!(
            *monthly_rewards.rewards.get(&np1.to_string()).unwrap(),
            (4 * 240) + 456
        );
        // NP2: 11 'type0' nodes in 'Europe,CH,Zurich' + 7 'type2' nodes in 'CH'
        assert_eq!(
            *monthly_rewards.rewards.get(&np2.to_string()).unwrap(),
            (11 * 68) + (7 * 11)
        );
    }

    #[test]
    fn test_get_node_providers_monthly_xdr_rewards_type3() {
        let registry = registry_init_empty();

        ///////////////////////////////
        // Adding two Node Providers and no reward table yet
        ///////////////////////////////
        let np1 = *TEST_USER1_PRINCIPAL;
        let registry = registry_add_node_operator(
            registry,
            np1,
            np1,
            "ZH3".to_string(),
            "Europe,CH,Zurich".into(),
            28,
            btreemap! { "type0".to_string() => 14, "type2".to_string() => 11 },
        );

        let np2 = *TEST_USER2_PRINCIPAL;
        let mut registry = registry_add_node_operator(
            registry,
            np2,
            np2,
            "ZH4".to_string(),
            "Europe,CH,Zurich".into(),
            28,
            btreemap! { "type3".to_string() => 14 },
        );

        ///////////////////////////////
        // Now add the reward table for type0/2/3 nodes and check that the values are properly used
        ///////////////////////////////
        let json = r#"{
            "North America,US":            { "type0": [100000, null],  "type2": [200000, null],  "type3": [300000, 70] },
            "North America,CA":            { "type0": [400000, null],  "type2": [500000, null],  "type3": [600000, 70] },
            "North America,US,California": { "type0": [700000, null],                            "type3": [800000, 70] },
            "North America,US,Florida":    { "type0": [900000, null],                            "type3": [1000000, 70] },
            "North America,US,Georgia":    { "type0": [1100000, null],                           "type3": [1200000, null] },
            "Asia,SG":                     { "type0": [10000000, 100],  "type2": [11000000, 100],  "type3": [12000000, 70] },
            "Asia":                        { "type0": [13000000, 100],  "type2": [14000000, 100],  "type3": [15000000, 70] },
            "Europe":                      { "type0": [20000000, null], "type2": [21000000, null], "type3": [22000000, 70] }
        }"#;

        let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
            serde_json::from_str(json).unwrap();
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
        registry.do_update_node_rewards_table(node_rewards_payload);

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();

        assert_eq!(
            monthly_rewards.registry_version,
            Some(registry.latest_version())
        );

        // NP1: the existence of type3 nodes should not impact the type0/type2 rewards
        assert_eq!(
            *monthly_rewards.rewards.get(&np1.to_string()).unwrap(),
            14 * 20000000 + 11 * 21000000
        );
        // NP2: type3 rewards are getting lower with each node the NP has
        // https://wiki.internetcomputer.org/wiki/Node_Provider_Remuneration
        let mut np2_expected_reward_ch = 0;
        let mut node_reward_ch = 22000000.0;
        for _ in 0..14 {
            println!("node_reward CH {}", node_reward_ch);
            np2_expected_reward_ch += node_reward_ch as u64;
            node_reward_ch *= 0.7;
        }
        assert_eq!(
            *monthly_rewards.rewards.get(&np2.to_string()).unwrap(),
            np2_expected_reward_ch
        );

        ///////////////////////////////
        // Now NP2 adds a new type3 DC in a different country (Germany), the rewards for the NP are again counted from the start
        ///////////////////////////////
        let no3 = *TEST_USER3_PRINCIPAL;
        let registry = registry_add_node_operator(
            registry,
            np2,
            no3,
            "FR2".to_string(),
            "Europe,DE,Frankfurt".into(),
            11,
            btreemap! { "type3".to_string() => 11 },
        );

        let mut np2_expected_reward_de = 0;
        let mut node_reward_de = 22000000.0;
        for _ in 0..11 {
            println!("node_reward DE {}", node_reward_de);
            np2_expected_reward_de += node_reward_de as u64;
            node_reward_de *= 0.7;
        }

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();
        assert_eq!(
            *monthly_rewards.rewards.get(&np2.to_string()).unwrap(),
            np2_expected_reward_ch + np2_expected_reward_de
        );

        ///////////////////////////////
        // Now NP2 adds a new type3 DC in the same country as before, the rewards for the NP continue decreasing per node, even across DCs
        ///////////////////////////////
        let no4 = *TEST_USER4_PRINCIPAL;
        let registry = registry_add_node_operator(
            registry,
            np2,
            no4,
            "BA1".to_string(),
            "Europe,CH,Basel".into(),
            10,
            btreemap! { "type3".to_string() => 10 },
        );

        for _ in 0..10 {
            println!("node_reward CH {}", node_reward_ch);
            np2_expected_reward_ch += node_reward_ch as u64;
            node_reward_ch *= 0.7;
        }

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();
        assert_eq!(
            *monthly_rewards.rewards.get(&np2.to_string()).unwrap(),
            np2_expected_reward_ch + np2_expected_reward_de
        );
    }
}
