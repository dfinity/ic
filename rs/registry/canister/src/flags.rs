use std::cell::Cell;

#[cfg(test)]
use ic_nervous_system_temporary::Temporary;

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(cfg!(feature = "test")) };

    static IS_CANISTER_RANGES_ROUTING_MAP_STORAGE_ENABLED: Cell<bool> = const { Cell::new(cfg!(feature = "test")) };
}

pub(crate) fn is_chunkifying_large_values_enabled() -> bool {
    IS_CHUNKIFYING_LARGE_VALUES_ENABLED.get()
}

#[cfg(test)]
pub fn temporarily_enable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, true)
}

#[cfg(test)]
pub(crate) fn temporarily_disable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, false)
}

pub(crate) fn is_canister_ranges_routing_map_storage_enabled() -> bool {
    IS_CANISTER_RANGES_ROUTING_MAP_STORAGE_ENABLED.get()
}

#[cfg(test)]
pub fn temporarily_enable_canister_ranges_routing_map_storage() -> Temporary {
    Temporary::new(&IS_CANISTER_RANGES_ROUTING_MAP_STORAGE_ENABLED, true)
}

#[cfg(test)]
pub fn temporarily_disable_canister_ranges_routing_map_storage() -> Temporary {
    Temporary::new(&IS_CANISTER_RANGES_ROUTING_MAP_STORAGE_ENABLED, false)
}
