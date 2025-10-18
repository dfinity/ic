use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
use ic_base_types::{NodeId, SubnetId};
use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetRecord};
use ic_registry_keys::{make_node_record_key, make_subnet_record_key};
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use prost::Message;
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
        self.validate_set_subnet_operational_level(&payload);
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

    fn validate_set_subnet_operational_level(&self, payload: &SetSubnetOperationalLevelPayload) {
        let SetSubnetOperationalLevelPayload {
            subnet_id,
            operational_level,
            ssh_readonly_access,
            ssh_node_state_write_access,
        } = payload;

        match subnet_id {
            None => {
                assert_eq!(
                    operational_level, &None,
                    "operational_level specified, but not subnet_id."
                );
                assert_eq!(
                    ssh_readonly_access, &None,
                    "ssh_readonly_access specified, but not subnet_id."
                );
            }

            Some(_subnet_id) => {
                // Nothing to do here.
            }
        }

        validate_operational_level(*operational_level);
        validate_ssh_readonly_access(ssh_readonly_access);
        validate_ssh_node_state_write_access(ssh_node_state_write_access);
    }
}

fn validate_operational_level(operational_level: Option<i32>) {
    // None is ok.
    let Some(operational_level) = operational_level else {
        return;
    };

    assert!(
        operational_level::ALL_VALID_CODES.contains(&operational_level),
        "Specified {} for operational_level, but that is not one of the allowed values",
        operational_level,
    );
}

fn validate_ssh_readonly_access(_ssh_readonly_access: &Option<Vec<String>>) {
    // Nothing to do here.
}

fn validate_ssh_node_state_write_access(ssh_node_state_write_access: &Option<Vec<NodeSshAccess>>) {
    // None is ok.
    let Some(ssh_node_state_write_access) = ssh_node_state_write_access.as_ref() else {
        return;
    };

    // Each element must be valid.
    ssh_node_state_write_access
        .iter()
        .for_each(validate_node_ssh_access);

    // The node_ids must be unique.
    let node_ids = ssh_node_state_write_access
        .iter()
        .map(|e| e.node_id)
        .collect::<HashSet<_>>();
    assert_eq!(
        node_ids.len(),
        ssh_node_state_write_access.len(),
        "node_ids in ssh_node_state_write_access are not unique: {ssh_node_state_write_access:?}",
    );
}

fn validate_node_ssh_access(node_ssh_access: &NodeSshAccess) {
    let NodeSshAccess {
        node_id,
        public_keys,
    } = node_ssh_access;

    assert!(
        node_id.is_some(),
        "node_id must be specified in NodeSshAccess."
    );

    // We could treat None the same as Some(vec![]), but that would make it far
    // too easy to commit unintentional deletion. (Some(vec![]) tells us to
    // clear the field!) Always make sure that clobbering is INTENTIONAL!
    assert!(
        public_keys.is_some(),
        "public_keys must be specified in NodeSshAccess."
    );
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
        .map(|node_ssh_access| {
            let NodeSshAccess {
                node_id,
                public_keys,
            } = node_ssh_access;

            // Assuming validate_set_subnet_operational_level is correct,
            // these unwraps will not panic.
            let node_id = node_id.unwrap();

            let mut node_record = node_record_fetcher(node_id);

            node_record.ssh_node_state_write_access = public_keys.unwrap_or_default();

            // This could be skipped if the original value of
            // ssh_node_state_write_access == public_keys, but for simplicity,
            // we just "brute force" it, i.e. create a mutation for every
            // element, even if it's not really needed.
            update(
                make_node_record_key(node_id).into_bytes(),
                node_record.encode_to_vec(),
            )
        })
        .collect()
}

/// Argument to the set_subnet_operational_level Registry canister method.
#[derive(Debug, Clone, Eq, PartialEq, CandidType, Deserialize)]
pub struct SetSubnetOperationalLevelPayload {
    subnet_id: Option<SubnetId>,
    operational_level: Option<i32>,
    ssh_readonly_access: Option<Vec<String>>,
    ssh_node_state_write_access: Option<Vec<NodeSshAccess>>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct NodeSshAccess {
    node_id: Option<NodeId>,
    public_keys: Option<Vec<String>>,
}
