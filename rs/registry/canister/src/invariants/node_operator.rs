use std::convert::TryFrom;

use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_keys::{make_node_operator_record_key, NODE_RECORD_KEY_PREFIX};

use crate::invariants::common::{InvariantCheckError, RegistrySnapshot};

use ic_base_types::PrincipalId;
use ic_nns_common::registry::decode_or_panic;

/// Node operator invariants hold iff:
///    * All node operators referred to in node records are registered
pub(crate) fn check_node_operator_invariants(
    snapshot: &RegistrySnapshot,
    strict: bool,
) -> Result<(), InvariantCheckError> {
    if strict {
        for node_record in get_all_node_records(snapshot) {
            let node_operator_id =
                PrincipalId::try_from(node_record.node_operator_id.clone()).unwrap();
            let key = make_node_operator_record_key(node_operator_id);
            match snapshot.get(key.as_bytes()) {
                Some(node_operator_record_vec) => {
                    decode_or_panic::<NodeOperatorRecord>((*node_operator_record_vec).clone());
                }
                None => {
                    return Err(InvariantCheckError {
                        msg: format!("Node operator {:} not in snapshot", node_operator_id),
                        source: None,
                    });
                }
            }
        }
    }
    Ok(())
}

// Return all node records in the snapshot
fn get_all_node_records(snapshot: &RegistrySnapshot) -> Vec<NodeRecord> {
    let mut nodes: Vec<NodeRecord> = Vec::new();
    for (k, v) in snapshot {
        if k.starts_with(NODE_RECORD_KEY_PREFIX.as_bytes()) {
            let record = decode_or_panic::<NodeRecord>(v.clone());
            nodes.push(record);
        }
    }
    nodes
}
