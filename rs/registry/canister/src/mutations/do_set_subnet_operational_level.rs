use crate::{common::LOG_PREFIX, registry::Registry};

use candid::CandidType;
use ic_base_types::{NodeId, SubnetId};
use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetRecord};
use ic_registry_keys::{make_node_record_key, make_subnet_record_key};
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub mod operational_level {
    pub const NORMAL: i32 = 1;
    pub const DOWN_FOR_REPAIRS: i32 = 2;

    pub const ALL_VALID_CODES: [i32; 2] = [NORMAL, DOWN_FOR_REPAIRS];

    pub fn name(code: i32) -> Option<&'static str> {
        let name = match code {
            NORMAL => "normal",
            DOWN_FOR_REPAIRS => "down_for_repairs",
            _ => {
                return None;
            }
        };

        Some(name)
    }

    pub fn code(name: &str) -> Option<i32> {
        let code = match name {
            "normal" => NORMAL,
            "down_for_repairs" => DOWN_FOR_REPAIRS,
            _ => {
                return None;
            }
        };

        Some(code)
    }
}

impl Registry {
    pub fn do_set_subnet_operational_level(&mut self, payload: SetSubnetOperationalLevelPayload) {
        println!("{LOG_PREFIX}do_set_subnet_operational_level: {payload:?}");
        self.validate_set_subnet_operational_level(&payload)
            .unwrap();
        let SetSubnetOperationalLevelPayload {
            subnet_id,
            operational_level,
            ssh_readonly_access,
            ssh_node_state_write_access,
        } = payload;

        let mut mutations: Vec<RegistryMutation> = vec![];

        // Change SubnetRecord.
        if let Some(subnet_id) = subnet_id {
            mutations.push(modify_subnet_record_for_set_subnet_operational_level(
                subnet_id,
                self.get_subnet_or_panic(subnet_id),
                operational_level,
                ssh_readonly_access,
            ));
        }

        // Change NodeRecord(s).
        mutations.append(&mut modify_node_record_for_set_subnet_operational_level(
            ssh_node_state_write_access,
            |node_id| self.get_node_or_panic(node_id),
        ));

        self.maybe_apply_mutation_internal(mutations);
    }

    fn validate_set_subnet_operational_level(
        &self,
        payload: &SetSubnetOperationalLevelPayload,
    ) -> Result<(), String> {
        let SetSubnetOperationalLevelPayload {
            subnet_id,
            operational_level,
            ssh_readonly_access,
            ssh_node_state_write_access,
        } = payload;

        match subnet_id {
            None => {
                if operational_level.is_some() {
                    return Err("operational_level specified, but not subnet_id.".to_string());
                }
                if ssh_readonly_access.is_some() {
                    return Err("ssh_readonly_access specified, but not subnet_id.".to_string());
                }

                if ssh_node_state_write_access.is_none() {
                    return Err("Request contains no changes at all!".to_string());
                }
            }

            Some(_subnet_id) => {
                // Nothing to do here.
            }
        }

        validate_operational_level(*operational_level)?;
        validate_ssh_readonly_access(ssh_readonly_access)?;
        validate_ssh_node_state_write_access(ssh_node_state_write_access)?;

        Ok(())
    }
}

fn validate_operational_level(operational_level: Option<i32>) -> Result<(), String> {
    // None is ok. None just means that is_halted does not get changed. Although
    // this is not how this field would generally be used in practice, not
    // having to specify an operational_level could be useful for when you want
    // the other effects of set_subnet_operational_level (i.e. setting ssh
    // access).
    let Some(operational_level) = operational_level else {
        return Ok(());
    };

    if !operational_level::ALL_VALID_CODES.contains(&operational_level) {
        return Err(format!(
            "Specified {operational_level} for operational_level, \
             but that is not one of the allowed values"
        ));
    };

    Ok(())
}

fn validate_ssh_readonly_access(_ssh_readonly_access: &Option<Vec<String>>) -> Result<(), String> {
    Ok(())
}

fn validate_ssh_node_state_write_access(
    ssh_node_state_write_access: &Option<Vec<NodeSshAccess>>,
) -> Result<(), String> {
    // None is ok. Remarks about when operational_level is None also apply here:
    // None means no change.
    let Some(ssh_node_state_write_access) = ssh_node_state_write_access.as_ref() else {
        return Ok(());
    };

    // Each element must be valid.
    ssh_node_state_write_access
        .iter()
        .map(validate_node_ssh_access)
        .collect::<Result<Vec<()>, String>>()?;

    // The node_ids must be unique.
    let node_ids = ssh_node_state_write_access
        .iter()
        .map(|e| e.node_id)
        .collect::<HashSet<_>>();
    if node_ids.len() != ssh_node_state_write_access.len() {
        return Err(format!(
            "node_ids in ssh_node_state_write_access are not unique: \
             {ssh_node_state_write_access:?}",
        ));
    }

    Ok(())
}

fn validate_node_ssh_access(node_ssh_access: &NodeSshAccess) -> Result<(), String> {
    let NodeSshAccess {
        node_id,
        public_keys,
    } = node_ssh_access;

    let Some(_node_id) = node_id else {
        return Err("node_id must be specified in NodeSshAccess.".to_string());
    };

    // We could treat None the same as Some(vec![]), but that would make it far
    // too easy to commit unintentional deletion. (Some(vec![]) tells us to
    // clear the field!) Always make sure that clobbering is INTENTIONAL!
    let Some(_public_keys) = public_keys else {
        return Err("public_keys must be specified in NodeSshAccess.".to_string());
    };

    Ok(())
}

/// Returns mutation(s) (possibly 0) to subnet_record to effect
/// operational_level and ssh_readonly_access.
fn modify_subnet_record_for_set_subnet_operational_level(
    subnet_id: SubnetId,
    mut subnet_record: SubnetRecord,
    operational_level: Option<i32>,
    ssh_readonly_access: Option<Vec<String>>,
) -> RegistryMutation {
    if let Some(operational_level) = operational_level {
        let is_halted = match operational_level {
            operational_level::NORMAL => false,
            operational_level::DOWN_FOR_REPAIRS => true,
            _ => panic!("Unknown operational_level"),
        };

        subnet_record.is_halted = is_halted;
    }

    if let Some(ssh_readonly_access) = ssh_readonly_access {
        subnet_record.ssh_readonly_access = ssh_readonly_access;
    }

    update(
        make_subnet_record_key(subnet_id).into_bytes(),
        subnet_record.encode_to_vec(),
    )
}

fn modify_node_record_for_set_subnet_operational_level(
    ssh_node_state_write_access: Option<Vec<NodeSshAccess>>,
    node_record_fetcher: impl Fn(NodeId) -> NodeRecord,
) -> Vec<RegistryMutation> {
    // Upgrade each element into a NodeRecord mutation.
    ssh_node_state_write_access
        .unwrap_or_default() // Treat None the same as Some(vec![])
        .into_iter()
        .filter_map(|node_ssh_access| {
            let NodeSshAccess {
                node_id,
                public_keys,
            } = node_ssh_access;

            // Assuming validate_set_subnet_operational_level is correct,
            // these unwraps will not panic.
            let node_id = node_id.unwrap();
            let public_keys = public_keys.unwrap();

            let mut node_record = node_record_fetcher(node_id);

            if node_record.ssh_node_state_write_access == public_keys {
                return None;
            }

            node_record.ssh_node_state_write_access = public_keys;
            Some(update(
                make_node_record_key(node_id).into_bytes(),
                node_record.encode_to_vec(),
            ))
        })
        .collect()
}

/// Argument to the set_subnet_operational_level Registry canister method.
#[derive(Debug, Clone, Eq, PartialEq, CandidType, Serialize, Deserialize)]
pub struct SetSubnetOperationalLevelPayload {
    pub subnet_id: Option<SubnetId>,
    pub operational_level: Option<i32>,
    pub ssh_readonly_access: Option<Vec<String>>,
    pub ssh_node_state_write_access: Option<Vec<NodeSshAccess>>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize, Deserialize)]
pub struct NodeSshAccess {
    pub node_id: Option<NodeId>,
    pub public_keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests;
