use crate::{common::LOG_PREFIX, registry::Registry};

use ic_cdk::println;
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue, registry_mutation};
use prost::Message;

impl Registry {
    /// Update the node rewards table
    pub fn do_update_node_rewards_table(&mut self, payload: UpdateNodeRewardsTableProposalPayload) {
        println!("{}do_update_node_rewards_table: {:?}", LOG_PREFIX, &payload);

        let mut node_rewards_table = self
            .get(NODE_REWARDS_TABLE_KEY.as_bytes(), self.latest_version())
            .map(|RegistryValue { value, .. }| NodeRewardsTable::decode(value.as_slice()).unwrap())
            .unwrap_or_default();

        node_rewards_table.extend(payload.get_rewards_table());

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: NODE_REWARDS_TABLE_KEY.into(),
            value: node_rewards_table.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}
