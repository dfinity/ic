use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{
    get_decoded_value, CanisterRegistryClient, CanisterRegistryClientExt, RegistryDataStableMemory,
};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, make_subnet_list_record_key,
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_types::registry::RegistryClientError;
use itertools::Itertools;
use rewards_calculation::rewards_calculator_results::DayUTC;
use rewards_calculation::types::{
    NodeType, ProviderRewardableNodes, Region, RewardPeriod, RewardableNode, UnixTsNanos,
};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::LocalKey;

pub struct RegistryQuerier {
    registry_client: Arc<dyn CanisterRegistryClient>,
}

struct NodeOperatorData {
    node_provider_id: PrincipalId,
    dc_id: String,
    region: Region,
}

impl RegistryQuerier {
    pub fn new(registry_client: Arc<dyn CanisterRegistryClient>) -> Self {
        RegistryQuerier { registry_client }
    }

    ///  Returns a list of all subnets present in the registry at the specified version.
    pub fn subnets_list(&self, version: RegistryVersion) -> Vec<SubnetId> {
        let key = make_subnet_list_record_key();
        let record = self
            .registry_client
            .get_value(key.as_str(), version)
            .expect("Failed to get SubnetListRecord")
            .map(|v| {
                SubnetListRecord::decode(v.as_slice()).expect("Failed to decode SubnetListRecord")
            })
            .unwrap_or_default();

        record
            .subnets
            .into_iter()
            .map(|s| {
                SubnetId::from(PrincipalId::try_from(s.as_slice()).expect("Invalid subnet ID"))
            })
            .collect()
    }

    /// Returns the NodeRewardsTable at the specified version.
    pub fn get_rewards_table(&self, version: RegistryVersion) -> NodeRewardsTable {
        self.registry_client
            .get_value(NODE_REWARDS_TABLE_KEY, version)
            .expect("Failed to get NodeRewardsTable")
            .map(|v| {
                NodeRewardsTable::decode(v.as_slice()).expect("Failed to decode SubnetListRecord")
            })
            .unwrap_or_default()
    }
}

// Exposed API Methods
impl RegistryQuerier {
    /// Computes the set of rewardable nodes, grouped by node provider, for the given range of UTC days.
    ///
    /// A node is considered rewardable on a specific UTC day if it exists in the registry on that day.
    /// See the `nodes_in_registry_between` method for details on how this is determined.
    ///
    /// Nodes without a specified `node_reward_type` are excluded from the rewardable set.
    pub fn get_rewardable_nodes_per_provider(
        registry_client: &'static LocalKey<Arc<impl CanisterRegistryClientExt>>,
        reward_period: RewardPeriod,
    ) -> Result<BTreeMap<PrincipalId, ProviderRewardableNodes>, RegistryClientError> {
        let mut rewardable_nodes_per_provider: BTreeMap<_, ProviderRewardableNodes> =
            BTreeMap::new();
        let nodes_in_range =
            Self::nodes_in_registry_between(registry_client, reward_period.from, reward_period.to);

        for (node_id, (node_record, latest_version, rewardable_days)) in nodes_in_range {
            let node_operator_id: PrincipalId = node_record
                .node_operator_id
                .try_into()
                .expect("Failed to parse PrincipalId from node operator ID");

            let Some(NodeOperatorData {
                node_provider_id,
                dc_id,
                region,
                ..
            }) = Self::node_operator_data(registry_client, node_operator_id, latest_version)?
            else {
                ic_cdk::println!("Node {} has no NodeOperatorData: skipping", node_id);
                continue;
            };
            let Some(some_reward_type) = node_record.node_reward_type else {
                ic_cdk::println!("Node {} has no node_reward_type: skipping", node_id);
                // If the node does not have a node_reward_type, we skip it.
                continue;
            };

            let node_reward_type =
                NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");

            // TODO: Modify RewardableNode to use NodeRewardType instead of NodeType.
            let node_type = NodeType(node_reward_type.into());

            rewardable_nodes_per_provider
                .entry(node_provider_id)
                .or_insert(ProviderRewardableNodes {
                    provider_id: node_provider_id,
                    ..Default::default()
                })
                .rewardable_nodes
                .push(RewardableNode {
                    node_id,
                    rewardable_days,
                    node_type,
                    dc_id: dc_id.clone(),
                    region: region.clone(),
                });
        }
        Ok(rewardable_nodes_per_provider)
    }

    /// Returns a map of all nodes that were present in the registry in a day range.
    ///
    /// Let's define the following for a day `D` in the range:
    ///
    /// - `A`: the start of the day (00:00:00 UTC) for the day.
    /// - `B`: the end of the day (23:59:59 UTC) for the day.
    ///
    /// A node is considered to be in the registry on a day `D` if:
    ///
    /// - it has been added in a registry version corresponding to a timestamp ts <= `B`
    /// - it has NOT been removed in a registry version corresponding to a timestamp ts < `A`
    ///
    /// For each node, are returned:
    /// - the most recent `NodeRecord` before `B` inclusive,
    /// - the corresponding `RegistryVersion`,
    /// - the sorted list of `DayUTC`s the node is in the registry.
    fn nodes_in_registry_between(
        registry_client: &'static LocalKey<Arc<impl CanisterRegistryClientExt>>,
        day_start: DayUTC,
        day_end: DayUTC,
    ) -> BTreeMap<NodeId, (NodeRecord, RegistryVersion, Vec<DayUTC>)> {
        let start_ts = day_start.unix_ts_at_day_start();
        let end_ts = day_end.unix_ts_at_day_end();
        let prefix_length = NODE_RECORD_KEY_PREFIX.len();

        registry_client.with(|registry_client| {
            registry_client.with_registry_map(|registry_map| {
                registry_map
                    .into_iter()
                    .filter(|(key, _, ts, _)| {
                        ts <= &end_ts && key.starts_with(NODE_RECORD_KEY_PREFIX)
                    })
                    .group_by(|(node_key, _, _, _)| node_key.clone())
                    .into_iter()
                    .filter_map(|(node_key, node_mutations)| {
                        let mut days = BTreeSet::new();
                        let mut last_present_ts: Option<UnixTsNanos> = None;
                        let mut latest_value: Option<Vec<u8>> = None;
                        let mut latest_version: RegistryVersion = RegistryVersion::default();

                        // Process node's mutations history.
                        for (_, version, ts, maybe_value) in node_mutations {
                            if maybe_value.is_some() {
                                // A creation or update
                                latest_value = maybe_value;
                                latest_version = version;
                                if last_present_ts.is_none() {
                                    // Node was absent, now it's present.
                                    // If it became present before the window, track it from the start.
                                    // Otherwise, track it from the actual timestamp.
                                    last_present_ts = Some(ts.max(start_ts));
                                }
                            } else {
                                // A deletion
                                if let Some(start_of_interval) = last_present_ts.take() {
                                    // The node was present and is now gone. Finalize the interval.
                                    let days_between = DayUTC::from(start_of_interval)
                                        .days_until(&DayUTC::from(ts));
                                    days.extend(days_between.unwrap_or_default());
                                }
                            }
                        }

                        // After all mutations, if the node is still present, finalize the last interval.
                        if let Some(start_of_interval) = last_present_ts {
                            let days_between =
                                DayUTC::from(start_of_interval).days_until(&DayUTC::from(end_ts));
                            days.extend(days_between.unwrap_or_default());
                        }

                        // If the node was present at any time and we have its record, decode and return it.
                        if !days.is_empty() {
                            if let Some(final_value) = latest_value {
                                let principal = PrincipalId::from_str(&node_key[prefix_length..])
                                    .expect("Invalid node key");
                                let node_id = NodeId::from(principal);
                                let node_record = NodeRecord::decode(final_value.as_slice())
                                    .expect("Failed to decode NodeRecord");

                                return Some((
                                    node_id,
                                    (
                                        node_record,
                                        latest_version,
                                        days.into_iter().sorted().collect(),
                                    ),
                                ));
                            }
                        }
                        None
                    })
                    .collect()
            })
        })
    }

    fn node_operator_data(
        registry_client: &'static LocalKey<Arc<impl CanisterRegistryClientExt>>,
        node_operator: PrincipalId,
        version: RegistryVersion,
    ) -> Result<Option<NodeOperatorData>, RegistryClientError> {
        let node_operator_record_key = make_node_operator_record_key(node_operator);
        let client = registry_client.with(|c| c.clone());
        let Some(node_operator_record) = get_decoded_value::<NodeOperatorRecord>(
            &*client,
            node_operator_record_key.as_str(),
            version,
        )
        .map_err(|e| RegistryClientError::DecodeError {
            error: format!("Failed to decode NodeOperatorRecord: {}", e),
        })?
        else {
            return Ok(None);
        };

        let data_center_key = make_data_center_record_key(node_operator_record.dc_id.as_str());
        let Some(data_center_record) =
            get_decoded_value::<DataCenterRecord>(&*client, data_center_key.as_str(), version)
                .map_err(|e| RegistryClientError::DecodeError {
                    error: format!("Failed to decode DataCenterRecord: {}", e),
                })?
        else {
            return Ok(None);
        };

        let node_provider_id: PrincipalId = node_operator_record
            .node_provider_principal_id
            .try_into()
            .expect("Failed to parse PrincipalId");
        let dc_id = node_operator_record.dc_id;
        let region = Region(data_center_record.region.clone());

        Ok(Some(NodeOperatorData {
            node_provider_id,
            dc_id,
            region,
        }))
    }
}

#[cfg(test)]
mod tests;
