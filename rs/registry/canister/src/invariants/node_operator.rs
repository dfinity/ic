use std::convert::TryFrom;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use prost::Message;

use crate::invariants::common::{InvariantCheckError, RegistrySnapshot, get_all_node_records};

/// Node operator invariants hold iff:
///    * All node operators referred to in node records are registered
pub(crate) fn check_node_operator_invariants(
    snapshot: &RegistrySnapshot,
    strict: bool,
) -> Result<(), InvariantCheckError> {
    if strict {
        for node_record in get_all_node_records(snapshot) {
            let node_operator_id = PrincipalId::try_from(node_record.node_operator_id).unwrap();
            let key = make_node_operator_record_key(node_operator_id);
            match snapshot.get(key.as_bytes()) {
                Some(node_operator_record_vec) => {
                    NodeOperatorRecord::decode(node_operator_record_vec.as_slice()).unwrap();
                }
                None => {
                    return Err(InvariantCheckError {
                        msg: format!("Node operator {node_operator_id:} not in snapshot"),
                        source: None,
                    });
                }
            }
        }
    }
    Ok(())
}
