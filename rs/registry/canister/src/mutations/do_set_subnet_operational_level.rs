use crate::registry::Registry;

use candid::{CandidType, Deserialize};
use ic_base_types::{NodeId, SubnetId};

impl Registry {
    pub fn do_set_subnet_operational_level(&mut self, _payload: SetSubnetOperationalLevelPayload) {
        // TODO(NNS1-4224): Implement.
        todo!();
    }
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
    public_key: Option<String>,
}
