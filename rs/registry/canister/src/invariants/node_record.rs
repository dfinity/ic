use std::collections::{BTreeMap, HashMap};

use ic_base_types::NodeId;
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;
use ic_protobuf::registry::node::v1::NodeRecord;

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, get_node_records_from_snapshot,
};

pub(crate) fn check_node_record_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let node_records = get_node_records_from_snapshot(snapshot);

    check_ssh_key_limits(&node_records)?;
    check_chip_ids_are_unique(&node_records)?;

    Ok(())
}

fn check_ssh_key_limits(
    node_records: &BTreeMap<NodeId, NodeRecord>,
) -> Result<(), InvariantCheckError> {
    for node_record in node_records.values() {
        // Enforce that the ssh_node_state_write_access field does not have too many elements.
        if node_record.ssh_node_state_write_access.len() > MAX_NUM_SSH_KEYS {
            return Err(InvariantCheckError {
                msg: format!(
                    "The `ssh_node_state_write_access` field of a `NodeRecord` has too many elements. \
                     {MAX_NUM_SSH_KEYS} is the maximum allowed; whereas, the `NodeRecord` with `http`=\
                     {} had {} elements \
                     in this field.",
                    node_record
                        .http
                        .as_ref()
                        .map(|http| format!("{http:?}"))
                        .unwrap_or_else(|| "?-UNKNOWN-?".to_string()),
                    node_record.ssh_node_state_write_access.len()
                ),
                source: None,
            });
        }
    }

    Ok(())
}

fn check_chip_ids_are_unique(
    node_records: &BTreeMap<NodeId, NodeRecord>,
) -> Result<(), InvariantCheckError> {
    let mut chip_id_to_node: HashMap<Vec<u8>, NodeId> = HashMap::new();

    for (node_id, node_record) in node_records {
        // Skip nodes without a chip_id (non-SEV nodes), or with an empty one.
        // Rejecting a malformed (empty) chip_id is not this check's job; here
        // we only care about uniqueness among meaningful values.
        let chip_id = match node_record.chip_id {
            Some(ref id) if !id.is_empty() => id,
            _ => continue,
        };

        if let Some(prev_node_id) = chip_id_to_node.get(chip_id) {
            return Err(InvariantCheckError {
                msg: format!(
                    "chip_id {} is assigned to multiple nodes: {} and {}",
                    hex::encode(chip_id),
                    prev_node_id,
                    node_id,
                ),
                source: None,
            });
        }

        chip_id_to_node.insert(chip_id.clone(), *node_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
