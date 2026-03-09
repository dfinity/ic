use std::cell::{Cell, RefCell};

use ic_nervous_system_access_list::AccessList;
#[cfg(any(test, feature = "canbench-rs"))]
use ic_nervous_system_temporary::Temporary;
use ic_types::{PrincipalId, SubnetId};

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(true) };
    static IS_NODE_SWAPPING_ENABLED: Cell<bool> = const { Cell::new(true) };

    // Temporary flags related to the node swapping feature.
    //
    // These are needed for the phased rollout approach in order
    // allow granular rolling out of the feature to specific subnets
    // to specific subset of callers.
    static NODE_SWAPPING_CALLERS_POLICY: RefCell<AccessList<PrincipalId>> = RefCell::new(AccessList::allow_all());

    static NODE_SWAPPING_SUBNETS_POLICY: RefCell<AccessList<SubnetId>> = RefCell::new(AccessList::allow_all());
}

pub(crate) fn is_chunkifying_large_values_enabled() -> bool {
    IS_CHUNKIFYING_LARGE_VALUES_ENABLED.get()
}

#[cfg(any(test, feature = "canbench-rs"))]
pub fn temporarily_enable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, true)
}

#[cfg(test)]
pub(crate) fn temporarily_disable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, false)
}

pub(crate) fn is_node_swapping_enabled() -> bool {
    IS_NODE_SWAPPING_ENABLED.get()
}

#[cfg(test)]
pub(crate) fn temporarily_disable_node_swapping() -> Temporary {
    Temporary::new(&IS_NODE_SWAPPING_ENABLED, false)
}

#[cfg(test)]
pub(crate) fn temporarily_enable_node_swapping() -> Temporary {
    Temporary::new(&IS_NODE_SWAPPING_ENABLED, true)
}

#[cfg(any(test, feature = "test"))]
pub mod temporary_overrides {
    use super::*;

    pub fn test_set_swapping_status(override_value: bool) {
        IS_NODE_SWAPPING_ENABLED.replace(override_value);
    }

    pub fn test_set_swapping_whitelisted_callers(override_callers: Vec<PrincipalId>) {
        let policy = AccessList::allow(override_callers);
        NODE_SWAPPING_CALLERS_POLICY.replace(policy);
    }

    pub fn test_set_swapping_enabled_subnets(override_subnets: Vec<SubnetId>) {
        let policy = AccessList::allow(override_subnets);
        NODE_SWAPPING_SUBNETS_POLICY.replace(policy);
    }
}

pub(crate) fn is_node_swapping_enabled_on_subnet(subnet_id: SubnetId) -> bool {
    NODE_SWAPPING_SUBNETS_POLICY.with_borrow(|subnet_policy| subnet_policy.is_allowed(&subnet_id))
}

pub(crate) fn is_node_swapping_enabled_for_caller(caller: PrincipalId) -> bool {
    NODE_SWAPPING_CALLERS_POLICY.with_borrow(|caller_policy| caller_policy.is_allowed(&caller))
}
