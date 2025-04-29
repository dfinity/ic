use ic_nervous_system_temporary::Temporary;
use std::cell::Cell;

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn is_chunkifying_large_values_enabled() -> bool {
    IS_CHUNKIFYING_LARGE_VALUES_ENABLED.get()
}

pub fn temporarily_enable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, true)
}

#[cfg(test)]
pub(crate) fn temporarily_disable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, false)
}
