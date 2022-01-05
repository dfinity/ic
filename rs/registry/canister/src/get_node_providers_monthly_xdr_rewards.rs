use crate::{pb::v1::NodeProvidersMonthlyXdrRewards, registry::Registry};
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_registry_keys::{
    make_data_center_record_key, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_types::PrincipalId;
use std::convert::TryFrom;
use std::str::from_utf8;

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

        let rewards_table = decode_or_panic::<NodeRewardsTable>(rewards_table_bytes);

        for (key, values) in self.store.iter() {
            if key.starts_with(NODE_OPERATOR_RECORD_KEY_PREFIX.as_bytes()) {
                let value = values.back().unwrap().value.clone();
                let node_operator = decode_or_panic::<NodeOperatorRecord>(value);

                let node_provider_id =
                    PrincipalId::try_from(&node_operator.node_provider_principal_id)
                        .map_err(|e| {
                            format!(
                                "Node Operator with key '{:?}' has a node_provider_principal_id \
                                 that cannot be parsed as a PrincipalId: '{}'",
                                from_utf8(key.as_slice()),
                                e
                            )
                        })?
                        .to_string();

                let dc_id = &node_operator.dc_id;
                let dc_key = make_data_center_record_key(dc_id);
                let dc_record_bytes = self
                    .get(dc_key.as_bytes(), self.latest_version())
                    .ok_or_else(|| {
                        format!("Data center ID '{}' was not found in the Registry", dc_id)
                    })?
                    .value
                    .clone();
                let dc = decode_or_panic::<DataCenterRecord>(dc_record_bytes);
                let region = &dc.region;
                let reward_rates = rewards_table.get(region).ok_or_else(|| {
                    format!(
                        "The Node Rewards Table does not have an entry for region '{}'",
                        region
                    )
                })?;

                let np_rewards = rewards.rewards.entry(node_provider_id).or_default();
                for (node_type, node_count) in node_operator.rewardable_nodes {
                    let rate = reward_rates.rates.get(&node_type).ok_or_else(|| {
                        format!(
                            "The Node Rewards Table does not have an entry for \
                             node type '{}' in region '{}'",
                            node_type, region
                        )
                    })?;
                    *np_rewards += node_count as u64 * rate.xdr_permyriad_per_node_per_month;
                }
            }
        }

        Ok(rewards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use ic_nns_constants::ids::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::dc::v1::AddOrRemoveDataCentersProposalPayload;
    use ic_protobuf::registry::node_rewards::v2::{
        NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload,
    };
    use maplit::btreemap;

    #[test]
    fn test_get_node_providers_monthly_xdr_rewards() {
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation());

        // Assert get_node_providers_monthly_xdr_rewards fails because no rewards table
        // exists in the Registry
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert_eq!(&err, "Node Rewards Table was not found in the Registry");

        // Add empty Node Rewards table to test failure cases
        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::default();
        registry.do_update_node_rewards_table(node_rewards_payload);

        // Add a Node Operator
        let rewardable_nodes_1 = btreemap! {
            "default".to_string() => 4,
        };

        let node_operator_payload_1 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_USER1_PRINCIPAL),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_USER1_PRINCIPAL),
            dc_id: "AN1".into(),
            rewardable_nodes: rewardable_nodes_1,
        };
        registry.do_add_node_operator(node_operator_payload_1);

        // Assert get_node_providers_monthly_xdr_rewards fails because the above Node
        // Operator's DC is not in the Registry
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert_eq!(&err, "Data center ID 'AN1' was not found in the Registry");

        // Add Data Centers
        let data_centers_to_add = vec![
            DataCenterRecord {
                id: "AN1".into(),
                region: "BEL".into(),
                owner: "Alice".into(),
                gps: None,
            },
            DataCenterRecord {
                id: "BC1".into(),
                region: "CAN".into(),
                owner: "Bob".into(),
                gps: None,
            },
        ];

        let dc_payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add,
            data_centers_to_remove: vec![],
        };

        registry.do_add_or_remove_data_centers(dc_payload);

        // Assert get_node_providers_monthly_xdr_rewards fails because rewards table
        // does not have an entry for the DC's region
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert_eq!(
            &err,
            "The Node Rewards Table does not have an entry for region 'BEL'"
        );

        // Add regions to rewards table (but an empty map to test failure cases)
        let new_entries = btreemap! {
            "BEL".to_string() =>  NodeRewardRates {
                rates: btreemap!{}
            },
        };

        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload { new_entries };
        registry.do_update_node_rewards_table(node_rewards_payload);

        // Assert get_node_providers_monthly_xdr_rewards fails because rewards table
        // does not have expected node type entries
        let err = registry
            .get_node_providers_monthly_xdr_rewards()
            .unwrap_err();
        assert_eq!(
            &err,
            "The Node Rewards Table does not have an entry for node type 'default' in region 'BEL'"
        );

        // Add the full rewards table
        let new_entries = btreemap! {
            "BEL".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 24,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 35,
                    },
                }
            },
            "CAN".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 68,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 11,
                    },
                }
            }
        };

        let node_rewards_payload = UpdateNodeRewardsTableProposalPayload { new_entries };
        registry.do_update_node_rewards_table(node_rewards_payload);

        let rewardable_nodes_2 = btreemap! {
            "default".to_string() => 11,
            "small".to_string() => 7,
        };

        let node_operator_payload_2 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_USER2_PRINCIPAL),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_USER2_PRINCIPAL),
            dc_id: "BC1".into(),
            rewardable_nodes: rewardable_nodes_2,
        };
        registry.do_add_node_operator(node_operator_payload_2);

        let monthly_rewards = registry.get_node_providers_monthly_xdr_rewards().unwrap();

        let np1 = TEST_USER1_PRINCIPAL.to_string();
        let np1_rewards = monthly_rewards.rewards.get(&np1).unwrap();
        let np2 = TEST_USER2_PRINCIPAL.to_string();
        let np2_rewards = monthly_rewards.rewards.get(&np2).unwrap();

        assert_eq!(*np1_rewards, 4 * 24);
        assert_eq!(*np2_rewards, (11 * 68) + (7 * 11));
    }
}
