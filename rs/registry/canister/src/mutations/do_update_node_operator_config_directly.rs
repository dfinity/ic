use std::convert::TryFrom;

use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

use prost::Message;

impl Registry {
    /// Update an existing Node Operator's config without going through the proposal process.
    /// Only the current NP specified in a record can make changes to that record's NP field.
    pub fn do_update_node_operator_config_directly(
        &mut self,
        payload: UpdateNodeOperatorConfigDirectlyPayload,
    ) {
        println!(
            "{}do_update_node_operator_config_directly: {:?}",
            LOG_PREFIX, payload
        );

        // 1. Look up the record of the requested target NodeOperatorRecord.
        let node_operator_id = payload
            .node_operator_id
            .expect("No Node Operator specified in the payload");
        let node_operator_record_key = make_node_operator_record_key(node_operator_id).into_bytes();
        let node_operator_record_vec = &self
            .get(&node_operator_record_key, self.latest_version())
            .unwrap_or_else(|| {
                panic!(
                    "{}Node Operator record with ID {} not found in the registry.",
                    LOG_PREFIX, node_operator_id
                )
            })
            .value;

        let mut node_operator_record =
            decode_registry_value::<NodeOperatorRecord>(node_operator_record_vec.clone());

        // 2. Make sure that the caller is authorized to make the requested changes to node_operator_record.
        let caller = dfn_core::api::caller();
        assert_eq!(
            caller,
            PrincipalId::try_from(&node_operator_record.node_provider_principal_id).unwrap()
        );

        // 3. Check that the Node Provider is not being set with the same ID as the Node Operator
        let node_provider_id = payload
            .node_provider_id
            .expect("No Node Provider specified in the payload");
        assert_ne!(
            node_provider_id, node_operator_id,
            "The Node Operator ID cannot be the same as the Node Provider ID: {}",
            node_operator_id
        );
        node_operator_record.node_provider_principal_id = node_provider_id.to_vec();

        // 4. Set and execute the mutation
        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: node_operator_record_key,
            value: encode_or_panic(&node_operator_record),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to update an existing Node Operator (without going through the proposal process)
///
/// See /rs/protobuf/def/registry/node_operator/v1/node_operator.proto
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Eq, Message)]
pub struct UpdateNodeOperatorConfigDirectlyPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    #[prost(message, optional, tag = "1")]
    pub node_operator_id: Option<PrincipalId>,

    /// The principal id of this node's provider.
    #[prost(message, optional, tag = "2")]
    pub node_provider_id: Option<PrincipalId>,
}
