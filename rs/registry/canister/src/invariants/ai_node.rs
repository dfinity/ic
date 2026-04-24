use std::collections::BTreeMap;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::ai_node::v1::AiNodeRecord;
use ic_registry_keys::{AI_NODE_RECORD_KEY_PREFIX, get_ai_node_record_node_id};
use prost::Message;

use super::common::{
    InvariantCheckError, RegistrySnapshot, get_node_record_from_snapshot,
    get_subnet_ids_from_snapshot,
};

/// Returns all AI node records from the snapshot.
fn get_ai_node_records_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> Result<BTreeMap<NodeId, AiNodeRecord>, InvariantCheckError> {
    let mut result = BTreeMap::<NodeId, AiNodeRecord>::new();
    for (key, value) in snapshot.iter() {
        let key_str = match String::from_utf8(key.clone()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if !key_str.starts_with(AI_NODE_RECORD_KEY_PREFIX) {
            continue;
        }

        if let Some(principal_id) = get_ai_node_record_node_id(&key_str) {
            let record =
                AiNodeRecord::decode(value.as_slice()).map_err(|err| InvariantCheckError {
                    msg: format!("Failed to decode AiNodeRecord for key={key_str}: {err}"),
                    source: None,
                })?;
            result.insert(NodeId::from(principal_id), record);
        }
    }
    Ok(result)
}

/// Checks AiNode invariants:
///    * Every AiNodeRecord has a corresponding NodeRecord
///    * If `subnet_id` is set, it must refer to a subnet that exists in the
///      registry
pub(crate) fn check_ai_node_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let ai_node_records = get_ai_node_records_from_snapshot(snapshot)?;
    let subnet_ids: std::collections::HashSet<SubnetId> =
        get_subnet_ids_from_snapshot(snapshot).into_iter().collect();

    for (ai_node_id, record) in ai_node_records {
        // NodeRecord must exist.
        let node_record = get_node_record_from_snapshot(ai_node_id, snapshot)?;
        if node_record.is_none() {
            return Err(InvariantCheckError {
                msg: format!(
                    "AI Node with id={ai_node_id} doesn't have a corresponding NodeRecord"
                ),
                source: None,
            });
        }

        // If subnet_id is set, it must parse and must refer to an existing
        // subnet in the snapshot.
        if let Some(raw) = record.subnet_id {
            let principal_id =
                PrincipalId::try_from(raw.as_slice()).map_err(|err| InvariantCheckError {
                    msg: format!("AI Node with id={ai_node_id} has a malformed subnet_id: {err}"),
                    source: None,
                })?;
            let subnet_id = SubnetId::from(principal_id);
            if !subnet_ids.contains(&subnet_id) {
                return Err(InvariantCheckError {
                    msg: format!(
                        "AI Node with id={ai_node_id} references subnet_id={subnet_id} that does not exist"
                    ),
                    source: None,
                });
            }
        }
    }

    Ok(())
}
