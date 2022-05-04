use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

use prost::Message;
use std::collections::BTreeMap;

impl Registry {
    /// Add a new Node Operator
    pub fn do_add_node_operator(&mut self, payload: AddNodeOperatorPayload) {
        println!("{}do_add_node_operator: {:?}", LOG_PREFIX, payload);

        let node_operator_record_key =
            make_node_operator_record_key(payload.node_operator_principal_id.unwrap()).into_bytes();
        let node_operator_record: NodeOperatorRecord = payload.into();

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: node_operator_record_key,
            value: encode_or_panic(&node_operator_record),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to add a new Node Operator
///
/// See /rs/protobuf/def/registry/node_operator/v1/node_operator.proto
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Eq, Message)]
pub struct AddNodeOperatorPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    ///
    /// This must be unique across NodeOperatorRecords.
    #[prost(message, optional, tag = "1")]
    pub node_operator_principal_id: Option<PrincipalId>,

    #[prost(message, optional, tag = "2")]
    pub node_provider_principal_id: Option<PrincipalId>,

    /// The remaining number of nodes that could be added by this Node Operator.
    #[prost(uint64, tag = "3")]
    pub node_allowance: u64,

    // The ID of the data center where this Node Operator hosts nodes.
    #[prost(string, tag = "4")]
    pub dc_id: String,

    // A map from node type to the number of nodes for which the associated Node
    // Provider should be rewarded.
    #[prost(btree_map = "string, uint32", tag = "5")]
    pub rewardable_nodes: BTreeMap<String, u32>,

    // The ipv6 address of the node's provider.
    #[prost(message, optional, tag = "6")]
    pub ipv6: Option<String>,
}

impl From<AddNodeOperatorPayload> for NodeOperatorRecord {
    fn from(val: AddNodeOperatorPayload) -> Self {
        NodeOperatorRecord {
            node_operator_principal_id: val.node_operator_principal_id.unwrap().to_vec(),
            node_provider_principal_id: val.node_provider_principal_id.unwrap().to_vec(),
            node_allowance: val.node_allowance,
            dc_id: val.dc_id,
            rewardable_nodes: val.rewardable_nodes,
            ipv6: val.ipv6,
        }
    }
}
