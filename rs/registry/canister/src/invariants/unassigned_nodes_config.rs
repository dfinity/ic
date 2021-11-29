use crate::{
    common::LOG_PREFIX,
    invariants::common::{get_value_from_snapshot, InvariantCheckError, RegistrySnapshot},
};

use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;

const MAX_NUM_SSH_KEYS: usize = 50;

/// Subnet invariants hold iff:
///    * Record does not exist OR it does, and each SSH key access list does not
///      contain more than 50 keys
pub(crate) fn check_unassigned_nodes_config_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    println!("{}check_unassigned_nodes_config_invariants", LOG_PREFIX);

    if let Some(config) = get_value_from_snapshot::<UnassignedNodesConfigRecord>(
        snapshot,
        make_unassigned_nodes_config_record_key(),
    ) {
        if config.ssh_readonly_access.len() > MAX_NUM_SSH_KEYS {
            return Err(InvariantCheckError {
                msg: format!(
                    "Mutation would have resulted in an SSH key access list that is too long, \
                    the maximum allowable length is {}, and the `readonly` list had {} keys",
                    MAX_NUM_SSH_KEYS,
                    config.ssh_readonly_access.len(),
                ),
                source: None,
            });
        }
    }

    Ok(())
}
