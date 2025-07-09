use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_nervous_system_canisters::registry::Registry;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{
    CanisterRegistryClient, RegistryDataStableMemory, StableCanisterRegistryClient,
    StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_keys::{
    make_subnet_list_record_key, DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX,
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_types::registry::RegistryClientError;
use indexmap::IndexMap;
use rewards_calculation::rewards_calculator_results::DayUTC;
use rewards_calculation::types::{
    NodeType, ProviderRewardableNodes, Region, RewardableNode, UnixTsNanos,
};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

pub trait RegistryEntry: RegistryValue {
    const KEY_PREFIX: &'static str;
}

impl RegistryEntry for DataCenterRecord {
    const KEY_PREFIX: &'static str = DATA_CENTER_KEY_PREFIX;
}

impl RegistryEntry for NodeOperatorRecord {
    const KEY_PREFIX: &'static str = NODE_OPERATOR_RECORD_KEY_PREFIX;
}

impl RegistryEntry for NodeRecord {
    const KEY_PREFIX: &'static str = NODE_RECORD_KEY_PREFIX;
}

impl RegistryEntry for NodeRewardsTable {
    const KEY_PREFIX: &'static str = NODE_REWARDS_TABLE_KEY;
}

pub struct RegistryClient<S: RegistryDataStableMemory> {
    store: Arc<StableCanisterRegistryClient<S>>,
}

struct NodeOperatorData {
    node_provider_id: PrincipalId,
    dc_id: String,
    region: Region,
}

enum RegistryRecordState {
    Present(UnixTsNanos),
    Deleted(UnixTsNanos),
}

struct RegistryRecordWithStates {
    key: String,
    value: Vec<u8>,
    registry_record_states: Vec<RegistryRecordState>,
}

impl<S: RegistryDataStableMemory> RegistryClient<S> {
    pub fn new(registry: Arc<dyn Registry>) -> Self {
        let store = Arc::new(StableCanisterRegistryClient::<S>::new(registry));
        RegistryClient { store }
    }

    pub fn store(&self) -> Arc<StableCanisterRegistryClient<S>> {
        self.store.clone()
    }

    pub async fn sync_registry_stored(&self) -> Result<RegistryVersion, String> {
        self.store.sync_registry_stored().await
    }

    pub fn get_versioned_value<T: RegistryValue + Default>(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> Result<T, RegistryClientError> {
        let value = self
            .store
            .get_versioned_value(key, version)?
            .map(|v| T::decode(v.as_slice()).unwrap())
            .value
            .unwrap_or_default();
        Ok(value)
    }

    pub fn get_value<T: RegistryValue + Default>(
        &self,
        key: &str,
    ) -> Result<T, RegistryClientError> {
        self.get_versioned_value::<T>(key, self.store.get_latest_version())
    }

    fn get_family_entries_of_version<T: RegistryEntry + Default>(
        &self,
        version: RegistryVersion,
    ) -> IndexMap<String, (u64, T)> {
        let prefix_length = T::KEY_PREFIX.len();

        self.store
            .get_key_family(T::KEY_PREFIX, version)
            .expect("Failed to get key family")
            .iter()
            .filter_map(|key| {
                let r = self
                    .store
                    .get_versioned_value(key, version)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to get entry {} for type {}",
                            key,
                            std::any::type_name::<T>()
                        )
                    });

                r.as_ref().map(|v| {
                    (
                        key[prefix_length..].to_string(),
                        (
                            r.version.get(),
                            T::decode(v.as_slice()).expect("Invalid registry value"),
                        ),
                    )
                })
            })
            .collect()
    }

    pub fn subnets_list(&self) -> Vec<SubnetId> {
        let record = self
            .get_value::<SubnetListRecord>(make_subnet_list_record_key().as_str())
            .expect("Failed to get subnets list");

        record
            .subnets
            .into_iter()
            .map(|s| SubnetId::from(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
            .collect()
    }

    pub fn get_rewards_table(&self) -> NodeRewardsTable {
        self.get_value::<NodeRewardsTable>(NODE_REWARDS_TABLE_KEY)
            .expect("Failed to get NodeRewardsTable")
    }

    /// Returns a list of all nodes that were present in the registry during the given UTC day range,
    /// along with their decoded `NodeRecord` and the exact days they were registered.
    ///
    /// A node is considered "in the registry" for a given UTC day if it has not been removed before
    /// the start of that day. This function identifies those nodes by analyzing the registry history
    /// over a specified timestamp range (`from` to `to`).
    fn nodes_in_registry(
        &self,
        from: DayUTC,
        to: DayUTC,
    ) -> Result<Vec<(NodeId, NodeRecord, Vec<DayUTC>)>, RegistryClientError> {
        let start_ts = from.unix_ts_at_day_start();
        let end_ts = to.unix_ts_at_day_end();
        let prefix_length = NodeRecord::KEY_PREFIX.len();

        let nodes_registry_changes = self.collect_nodes_registry_states(start_ts, end_ts)?;

        let result = nodes_registry_changes
            .into_iter()
            .map(
                |RegistryRecordWithStates {
                     key,
                     value,
                     registry_record_states: registry_changes,
                 }| {
                    let node_id = NodeId::from(
                        PrincipalId::from_str(&key[prefix_length..])
                            .expect("Failed to parse node id"),
                    );
                    let node_record =
                        NodeRecord::decode(value.as_slice()).expect("Failed to decode node record");
                    let days_in_registry =
                        self.expand_registry_changes_to_presence_days(&registry_changes, end_ts);

                    (node_id, node_record, days_in_registry)
                },
            )
            .collect();

        Ok(result)
    }

    fn collect_nodes_registry_states(
        &self,
        start_ts: UnixTsNanos,
        end_ts: UnixTsNanos,
    ) -> Result<Vec<RegistryRecordWithStates>, RegistryClientError> {
        let mut changes = IndexMap::new();
        let entries = self.nodes_entries_before(&end_ts);

        for (version_ts, node_key, StorableRegistryValue(maybe_value)) in entries {
            if version_ts < start_ts {
                if let Some(value) = maybe_value {
                    // If the value is present before the start_ts, we add it as a present since start_ts.
                    changes.insert(
                        node_key.key,
                        (value, vec![RegistryRecordState::Present(start_ts)]),
                    );
                } else {
                    changes.shift_remove(&node_key.key);
                }
            } else {
                match changes.get_mut(&node_key.key) {
                    Some((present_value, registry_changes)) => {
                        if let Some(value) = maybe_value {
                            *present_value = value;
                            if let Some(RegistryRecordState::Deleted(_)) = registry_changes.last() {
                                // If the last change was a deletion, it means the node was re-added.
                                registry_changes.push(RegistryRecordState::Present(version_ts));
                            }
                        } else {
                            // If the value is None, it means the node was deleted at this version.
                            registry_changes.push(RegistryRecordState::Deleted(version_ts));
                        }
                    }
                    None => {
                        // If the key is not present, the node was added inside the reward period.
                        if let Some(value) = maybe_value {
                            changes.insert(
                                node_key.key,
                                (value, vec![RegistryRecordState::Present(version_ts)]),
                            );
                        }
                    }
                }
            }
        }

        Ok(changes
            .into_iter()
            .map(
                |(key, (value, registry_changes))| RegistryRecordWithStates {
                    key,
                    value,
                    registry_record_states: registry_changes,
                },
            )
            .collect())
    }

    fn nodes_entries_before(
        &self,
        timestamp: &UnixTsNanos,
    ) -> Vec<(UnixTsNanos, StorableRegistryKey, StorableRegistryValue)> {
        let key_prefix = NodeRecord::KEY_PREFIX;
        let start_range = StorableRegistryKey {
            key: key_prefix.to_string(),
            ..Default::default()
        };

        let registry_version_to_timestamp_map: BTreeMap<RegistryVersion, UnixTsNanos> = self
            .store
            .timestamp_to_versions_map()
            .clone()
            .into_iter()
            .flat_map(|(ts, versions)| versions.into_iter().map(move |version| (version, ts)))
            .collect();

        S::with_registry_map(|map| {
            map.range(start_range..)
                .map(|(k, v)| {
                    let ts = registry_version_to_timestamp_map
                        .get(&RegistryVersion::from(k.version))
                        .expect("Failed to get timestamp for version");

                    (*ts, k, v)
                })
                .filter(|(ts, _, _)| ts <= timestamp)
                .take_while(|(_, k, _)| k.key.starts_with(key_prefix))
                .collect::<Vec<_>>()
        })
    }

    fn expand_registry_changes_to_presence_days(
        &self,
        changes: &[RegistryRecordState],
        end_ts: UnixTsNanos,
    ) -> Vec<DayUTC> {
        let mut days = Vec::new();
        let mut current_start: Option<DayUTC> = None;

        for change in changes {
            match change {
                RegistryRecordState::Present(ts) => {
                    current_start = Some(DayUTC::from(*ts));
                }
                RegistryRecordState::Deleted(ts) => {
                    if let Some(start) = current_start.take() {
                        let days_between = start
                            .days_until(&DayUTC::from(*ts))
                            .expect("Failed to get days between");
                        days.extend(days_between);
                    }
                }
            }
        }

        if let Some(start) = current_start {
            let days_between = start
                .days_until(&DayUTC::from(end_ts))
                .expect("Failed to get days between");
            days.extend(days_between);
        }

        days
    }

    fn node_operators_data(&self, day: DayUTC) -> HashMap<PrincipalId, NodeOperatorData> {
        let end_ts = day.unix_ts_at_day_end();
        let version_before_end_ts: RegistryVersion = *self
            .store
            .timestamp_to_versions_map()
            .range(..=end_ts)
            .next_back()
            .map(|(_, versions)| versions.iter().max().expect("Failed to get max version"))
            .expect("Failed to find a version before end_ts");
        let node_operators = self
            .get_family_entries_of_version::<NodeOperatorRecord>(version_before_end_ts)
            .into_iter()
            .map(|(_, (_, node_operator_record))| {
                (
                    PrincipalId::try_from(node_operator_record.node_operator_principal_id.clone())
                        .expect("Failed to parse PrincipalId"),
                    node_operator_record,
                )
            })
            .collect::<HashMap<_, _>>();
        let data_centers =
            self.get_family_entries_of_version::<DataCenterRecord>(version_before_end_ts);

        node_operators
            .into_iter()
            .map(|(node_operator_id, node_operator_record)| {
                let node_provider_id: PrincipalId = node_operator_record
                    .node_provider_principal_id
                    .try_into()
                    .expect("Failed to parse PrincipalId");
                let dc_id = node_operator_record.dc_id.clone();
                let (_, data_center_record) =
                    data_centers.get(&dc_id).expect("Failed to find dc_id");
                let region = Region(data_center_record.region.clone());

                let node_operator_data = NodeOperatorData {
                    node_provider_id,
                    dc_id,
                    region,
                };
                (node_operator_id, node_operator_data)
            })
            .collect()
    }

    /// Computes the set of rewardable nodes grouped by node provider for the given UTC day range.
    ///
    /// A node is considered rewardable for a given UTC day if it was registered in the registry
    /// at the start of that day and has not been removed prior.
    /// This means:
    /// - Nodes begin earning rewards starting from the UTC day they are registered.
    /// - Nodes stop earning rewards the UTC day after they are removed from the registry.
    ///
    /// Nodes removed before the `from` day or without a reward type are skipped.
    pub fn get_rewardable_nodes_per_provider(
        &self,
        from: DayUTC,
        to: DayUTC,
    ) -> Result<BTreeMap<PrincipalId, ProviderRewardableNodes>, RegistryClientError> {
        let mut rewardable_nodes_per_provider: BTreeMap<_, ProviderRewardableNodes> =
            BTreeMap::new();

        let nodes_in_range = self.nodes_in_registry(from, to)?;
        let node_operators_data = self.node_operators_data(to);

        for (node_id, node_record, rewardable_days) in nodes_in_range {
            let node_operator_id: PrincipalId = node_record.node_operator_id.try_into().unwrap();
            let Some(some_node_operator_data) = node_operators_data.get(&node_operator_id) else {
                // Reward only node operators that are registered in the registry at the end of the period
                continue;
            };
            let Some(some_reward_type) = node_record.node_reward_type else {
                // If the node does not have a reward type, we skip it.
                continue;
            };

            let node_reward_type =
                NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");
            let NodeOperatorData {
                node_provider_id,
                dc_id,
                region,
                ..
            } = some_node_operator_data;

            // TODO: Modify RewardableNode to use NodeRewardType instead of NodeType.
            let node_type = NodeType(node_reward_type.into());

            rewardable_nodes_per_provider
                .entry(*node_provider_id)
                .or_insert(ProviderRewardableNodes {
                    provider_id: *node_provider_id,
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
}

#[cfg(test)]
mod tests;
