use std::cell::{Cell, RefCell};

#[cfg(any(test, feature = "canbench-rs"))]
use ic_nervous_system_temporary::Temporary;
use ic_types::{PrincipalId, SubnetId};

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(true) };
    static IS_NODE_SWAPPING_ENABLED: Cell<bool> = const { Cell::new(false) };
    static NODE_SWAPPING_WHITELISTED_CALLERS: RefCell<Vec<PrincipalId>> = const { RefCell::new(Vec::new()) };
    static NODE_SWAPPING_ENABLED_SUBNETS: RefCell<Vec<SubnetId>> = const { RefCell::new(Vec::new()) };
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

pub(crate) fn is_node_swapping_enabled_on_subnet(subnet_id: SubnetId) -> bool {
    NODE_SWAPPING_ENABLED_SUBNETS
        .with_borrow(|enabled_subnets| enabled_subnets.contains(&subnet_id))
}

pub(crate) fn is_node_swapping_enabled_for_caller(caller: PrincipalId) -> bool {
    NODE_SWAPPING_WHITELISTED_CALLERS
        .with_borrow(|enabled_callers| enabled_callers.contains(&caller))
}

#[cfg(test)]
pub(crate) fn temporarily_enable_swapping_on_subnets(subnets: Vec<SubnetId>) {
    NODE_SWAPPING_ENABLED_SUBNETS.replace(subnets);
}

#[cfg(test)]
pub(crate) fn temporarily_enable_swapping_for_callers(callers: Vec<PrincipalId>) {
    NODE_SWAPPING_WHITELISTED_CALLERS.replace(callers);
}
