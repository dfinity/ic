use crate::mutations::node_management::common::{get_existing_records, get_subnet_list_record};
use crate::registry::Registry;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::NODE_OPERATOR_RECORD_KEY_PREFIX;
use ic_registry_keys::{DATA_CENTER_KEY_PREFIX, NODE_RECORD_KEY_PREFIX};
use ic_registry_node_provider_rewards::v1_types::{
    AHashMap, DailyNodeMetrics, NodesMetricsHistory, RewardableNode,
};
use ic_types::PrincipalId;
use itertools::Itertools;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;

impl Registry {
    async fn get_nodes_metrics(
        &self,
        from_ts: u64,
    ) -> Result<AHashMap<PrincipalId, Vec<DailyNodeMetrics>>, String> {
        let subnets = get_subnet_list_record(self)
            .subnets
            .into_iter()
            .map(|subnet_id| PrincipalId::try_from(subnet_id).unwrap())
            .collect_vec();

        let subnets_metrics = subnets
            .into_iter()
            .map(|subnet_id| {
                let contract = NodeMetricsHistoryArgs {
                    subnet_id,
                    start_at_timestamp_nanos: from_ts,
                };

                ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryResponse>,)>(
                    candid::Principal::management_canister(),
                    "node_metrics_history",
                    (contract,),
                    0_u128,
                )
                    .map(move |result| {
                        result
                            .map_err(|(code, msg)| {
                                format!(
                                    "Error when calling management canister for subnet {}:\n Code:{:?}\nMsg:{}",
                                    subnet_id,
                                    code,
                                    msg)
                            })
                            .map(|(node_metrics,)| node_metrics)
                    })
            });

        let subnets_metrics = futures::future::try_join_all(subnets_metrics)
            .await?
            .into_iter()
            .flatten()
            .collect_vec();

        Ok(NodesMetricsHistory(subnets_metrics).into())
    }

    pub(crate) async fn get_rewardable_nodes(
        &self,
        from_ts: u64,
        from_registry_version: u64,
    ) -> Result<Vec<RewardableNode>, String> {
        let mut nodes_in_period = Vec::new();
        let mut rewardable_nodes = BTreeMap::new();

        let mut nodes_metrics = self.get_nodes_metrics(from_ts).await?;

        let node_records = get_existing_records::<NodeRecord>(
            self,
            NODE_RECORD_KEY_PREFIX,
            &from_registry_version,
        )
        .collect_vec();

        let node_operators = get_existing_records::<NodeOperatorRecord>(
            self,
            NODE_OPERATOR_RECORD_KEY_PREFIX,
            &from_registry_version,
        )
        .collect::<BTreeMap<String, NodeOperatorRecord>>();

        let data_center_records = get_existing_records::<DataCenterRecord>(
            self,
            DATA_CENTER_KEY_PREFIX,
            &from_registry_version,
        )
        .collect::<BTreeMap<String, DataCenterRecord>>();

        for (p, node_record) in node_records {
            let principal = PrincipalId::from_str(p.as_str()).map_err(|e| e.to_string())?;

            let node_operator_id: String = node_record.node_operator_id.try_into().unwrap();
            let node_operator_record = node_operators.get(&node_operator_id).ok_or_else(|| {
                format!(
                    "Node Operator with id '{}' \
                        not found in the Registry",
                    node_operator_id
                )
            })?;
            let data_center_record = data_center_records
                .get(&node_operator_record.dc_id)
                .ok_or_else(|| {
                    format!(
                        "DataCenter with id '{}' \
                        not found in the Registry",
                        node_operator_id
                    )
                })?;
            let node_provider_id: PrincipalId = node_operator_record
                .node_provider_principal_id
                .clone()
                .try_into()
                .unwrap();

            if let Entry::Vacant(rewardables) = rewardable_nodes.entry(node_operator_id) {
                rewardables.insert(node_operator_record.rewardable_nodes.clone());
            }

            nodes_in_period.push(RewardableNode {
                node_id: principal,
                node_provider_id,
                region: data_center_record.region.clone(),
                node_type: match rewardable_nodes.get_mut(&node_operator_id) {
                    Some(rewardable_nodes) => {
                        if rewardable_nodes.is_empty() {
                            "unknown:no_rewardable_nodes_found".to_string()
                        } else {
                            let (k, mut v) = loop {
                                let (k, v) = match rewardable_nodes.pop_first() {
                                    Some(kv) => kv,
                                    None => {
                                        break ("unknown:rewardable_nodes_used_up".to_string(), 0)
                                    }
                                };
                                if v != 0 {
                                    break (k, v);
                                }
                            };
                            v = v.saturating_sub(1);
                            if v != 0 {
                                rewardable_nodes.insert(k.clone(), v);
                            }
                            k
                        }
                    }

                    None => "unknown".to_string(),
                },
                node_metrics: nodes_metrics.remove(&principal),
            });
        }

        Ok(nodes_in_period)
    }
}
