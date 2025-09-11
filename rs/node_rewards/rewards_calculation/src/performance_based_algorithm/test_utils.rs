use crate::types::{NodeMetricsDailyRaw, Region, RewardableNode};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use maplit::btreemap;
use std::collections::BTreeMap;

pub fn test_node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

pub fn test_provider_id(id: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(id)
}

pub fn test_subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

impl Default for RewardableNode {
    fn default() -> Self {
        RewardableNode {
            node_id: NodeId::from(PrincipalId::new_node_test_id(0)),
            region: Region::default(),
            node_reward_type: NodeRewardType::default(),
            dc_id: "default_dc".into(),
        }
    }
}

pub fn build_daily_metrics(
    subnet_id: SubnetId,
    nodes_data: &[(NodeId, u64, u64)],
) -> (SubnetId, Vec<NodeMetricsDailyRaw>) {
    let metrics = nodes_data
        .iter()
        .map(|(node_id, proposed, failed)| NodeMetricsDailyRaw {
            node_id: *node_id,
            num_blocks_proposed: *proposed,
            num_blocks_failed: *failed,
        })
        .collect();
    (subnet_id, metrics)
}

pub fn generate_rewardable_nodes(nodes_with_rewardable_days: Vec<NodeId>) -> Vec<RewardableNode> {
    nodes_with_rewardable_days
        .into_iter()
        .map(|node_id| RewardableNode {
            node_id,
            ..Default::default()
        })
        .collect()
}

pub fn create_rewards_table_for_region_test() -> NodeRewardsTable {
    let mut table = BTreeMap::new();
    table.insert(
        "Europe,Switzerland".to_string(),
        NodeRewardRates {
            rates: btreemap! {
                NodeRewardType::Type1.to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                    reward_coefficient_percent: None,
                },
            },
        },
    );
    table.insert(
        "North America,USA,California".to_string(),
        NodeRewardRates {
            rates: btreemap! {
                NodeRewardType::Type3.to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 913125, // -> 30000 / day
                    reward_coefficient_percent: Some(90),
                },
            },
        },
    );
    table.insert(
        "North America,USA,Nevada".to_string(),
        NodeRewardRates {
            rates: btreemap! {
                NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 1217500, // -> 40000 / day
                    reward_coefficient_percent: Some(70),
                },
            },
        },
    );
    NodeRewardsTable { table }
}
