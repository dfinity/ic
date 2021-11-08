use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

impl Registry {
    /// Update the node rewards table
    pub fn do_update_node_rewards_table(&mut self, payload: UpdateNodeRewardsTableProposalPayload) {
        println!("{}do_update_node_rewards_table: {:?}", LOG_PREFIX, &payload);

        let mut node_rewards_table = self
            .get(NODE_REWARDS_TABLE_KEY.as_bytes(), self.latest_version())
            .map(|RegistryValue { value, .. }| {
                decode_registry_value::<NodeRewardsTable>(value.clone())
            })
            .unwrap_or_else(NodeRewardsTable::default);

        node_rewards_table.extend(payload.get_rewards_table());

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: NODE_REWARDS_TABLE_KEY.into(),
            value: encode_or_panic(&node_rewards_table),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}
