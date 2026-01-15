use crate::invariants::common::{InvariantCheckError, RegistrySnapshot, get_all_node_records};
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;

pub(crate) fn check_node_record_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    for node_record in get_all_node_records(snapshot) {
        // Enforce that the ssh_node_state_write_access field does not have too many elements.
        if node_record.ssh_node_state_write_access.len() > MAX_NUM_SSH_KEYS {
            return Err(InvariantCheckError {
                msg: format!(
                    "The `ssh_node_state_write_access` field of a `NodeReocrd` has too many elements. \
                     {MAX_NUM_SSH_KEYS} is the maximum allowed; whereas, the `NodeRecord` with `chip_id`=\
                     {} had {} elements \
                     in this field.",
                    node_record
                        .http
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

#[cfg(test)]
mod tests;
