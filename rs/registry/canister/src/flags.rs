use std::cell::Cell;

#[cfg(any(test, feature = "canbench-rs"))]
use ic_nervous_system_temporary::Temporary;

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(true) };

    static IS_ROUTING_TABLE_SINGLE_ENTRY_OBSOLETE: Cell<bool> = const { Cell::new(cfg!(feature = "canbench-rs")) };
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

pub(crate) fn is_routing_table_single_entry_obsolete() -> bool {
    IS_ROUTING_TABLE_SINGLE_ENTRY_OBSOLETE.get()
}
